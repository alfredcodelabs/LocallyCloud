use std::collections::{BTreeMap, HashMap};

use crate::{error::SqsError, model::Message};

/// Internal enqueue order is reconstructed from SQLite row order, independently of AWS sequence numbers.
#[derive(Default)]
pub(crate) struct Messages {
    ordered: BTreeMap<u128, Message>,
    ids: HashMap<String, u128>,
    next: u128,
    #[cfg(test)]
    work: std::sync::atomic::AtomicUsize,
}

impl Messages {
    fn record_work(&self, count: usize) {
        #[cfg(test)]
        self.work
            .fetch_add(count, std::sync::atomic::Ordering::Relaxed);
        #[cfg(not(test))]
        let _ = count;
    }

    pub(crate) fn check_capacity(&self, additional: usize) -> Result<(), SqsError> {
        self.next
            .checked_add(additional as u128)
            .ok_or(SqsError::StorageUnavailable)?;
        Ok(())
    }

    pub(crate) fn check_insert(&self, id: &str) -> Result<(), SqsError> {
        self.record_work(1);
        if self.ids.contains_key(id) {
            return Err(SqsError::StorageUnavailable);
        }
        self.check_capacity(1)
    }

    pub(crate) fn push_back(&mut self, message: Message) -> Result<(), SqsError> {
        self.check_insert(&message.id)?;
        let next = self
            .next
            .checked_add(1)
            .ok_or(SqsError::StorageUnavailable)?;
        self.record_work(2);
        self.ids.insert(message.id.clone(), self.next);
        self.ordered.insert(self.next, message);
        self.next = next;
        Ok(())
    }

    pub(crate) fn get(&self, id: &str) -> Option<&Message> {
        self.record_work(1);
        let key = self.ids.get(id)?;
        self.record_work(1);
        self.ordered.get(key)
    }

    pub(crate) fn get_mut(&mut self, id: &str) -> Option<&mut Message> {
        self.record_work(1);
        let key = *self.ids.get(id)?;
        self.record_work(1);
        self.ordered.get_mut(&key)
    }

    pub(crate) fn remove(&mut self, id: &str) -> Option<Message> {
        self.record_work(1);
        let key = self.ids.remove(id)?;
        self.record_work(1);
        self.ordered.remove(&key)
    }

    pub(crate) fn iter(&self) -> impl DoubleEndedIterator<Item = &Message> {
        self.ordered.values().inspect(|_| self.record_work(1))
    }

    pub(crate) fn iter_mut(&mut self) -> impl DoubleEndedIterator<Item = &mut Message> {
        #[cfg(test)]
        let work = &self.work;
        self.ordered.values_mut().inspect(move |_| {
            #[cfg(test)]
            work.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        })
    }

    pub(crate) fn retain(&mut self, mut keep: impl FnMut(&Message) -> bool) {
        let mut visited = 0;
        self.ordered.retain(|_, message| {
            visited += 1;
            if keep(message) {
                true
            } else {
                self.ids.remove(&message.id);
                visited += 1;
                false
            }
        });
        self.record_work(visited);
    }

    pub(crate) fn clear(&mut self) {
        self.record_work(self.ordered.len() + self.ids.len());
        self.ordered.clear();
        self.ids.clear();
        self.next = 0;
    }

    pub(crate) fn len(&self) -> usize {
        self.ordered.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.ordered.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn take_work(&self) -> usize {
        self.work.swap(0, std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn message(id: &str) -> Message {
        Message {
            id: id.into(),
            body: id.into(),
            body_on_disk: false,
            encrypted_body: None,
            md5_body: String::new(),
            attributes: BTreeMap::new(),
            md5_attributes: None,
            system_attributes: BTreeMap::new(),
            group_id: None,
            dedup_id: None,
            sequence_number: None,
            sent_timestamp_ms: 0,
            queue_arrival_ms: None,
            receive_count: 0,
            first_receive_ms: None,
            visible_at: Instant::now(),
            receipt_handle: None,
        }
    }

    #[test]
    fn structural_mutations_preserve_order_and_reject_duplicate_or_exhausted_keys() {
        let mut messages = Messages::default();
        for id in ["a", "b", "c", "d"] {
            messages.push_back(message(id)).unwrap();
        }
        assert!(messages.push_back(message("b")).is_err());
        assert_eq!(messages.remove("b").unwrap().body, "b");
        messages.retain(|message| message.id != "a");
        messages.push_back(message("e")).unwrap();
        assert_eq!(
            messages
                .iter()
                .map(|message| message.id.as_str())
                .collect::<Vec<_>>(),
            ["c", "d", "e"]
        );
        assert!(messages.get("a").is_none() && messages.get("b").is_none());
        assert_eq!(messages.get("c").unwrap().body, "c");
        messages.next = u128::MAX;
        assert!(messages.check_insert("f").is_err());
        assert!(messages.push_back(message("f")).is_err());
        assert_eq!(messages.len(), 3);
        messages.next = u128::MAX - 1;
        assert!(messages.check_capacity(2).is_err());
        messages.clear();
        assert!(messages.is_empty());
        assert!(messages.get("c").is_none());
        messages.push_back(message("f")).unwrap();
        assert_eq!(messages.iter().next().unwrap().id, "f");
    }
}
