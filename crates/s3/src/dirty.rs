//! Mutation keys for incremental persistence; wire encoding remains a plain map.
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DirtyMap<K: Ord, V> {
    entries: BTreeMap<K, V>,
    #[serde(skip)]
    dirty: BTreeSet<K>,
}
impl<K: Ord, V> Default for DirtyMap<K, V> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            dirty: BTreeSet::new(),
        }
    }
}
impl<K: Ord + Clone, V> DirtyMap<K, V> {
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.dirty.insert(key.clone());
        self.entries.insert(key, value)
    }
    pub fn get_mut<Q: Ord + ?Sized>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
    {
        if let Some((key, _)) = self.entries.get_key_value(key) {
            self.dirty.insert(key.clone());
        }
        self.entries.get_mut(key)
    }
    pub fn remove<Q: Ord + ?Sized>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
    {
        if let Some((key, _)) = self.entries.get_key_value(key) {
            self.dirty.insert(key.clone());
        }
        self.entries.remove(key)
    }
    pub fn entry(&mut self, key: K) -> std::collections::btree_map::Entry<'_, K, V> {
        self.dirty.insert(key.clone());
        self.entries.entry(key)
    }
    pub(crate) fn take_dirty(&mut self) -> BTreeSet<K> {
        std::mem::take(&mut self.dirty)
    }
    pub(crate) fn untracked_mut(&mut self, key: &K) -> Option<&mut V> {
        self.entries.get_mut(key)
    }
    pub fn values_mut(&mut self) -> std::collections::btree_map::ValuesMut<'_, K, V> {
        self.dirty.extend(self.entries.keys().cloned());
        self.entries.values_mut()
    }
}
impl<K: Ord, V> Deref for DirtyMap<K, V> {
    type Target = BTreeMap<K, V>;
    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}
impl<K: Ord, V> IntoIterator for DirtyMap<K, V> {
    type Item = (K, V);
    type IntoIter = std::collections::btree_map::IntoIter<K, V>;
    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}
impl<'a, K: Ord, V> IntoIterator for &'a DirtyMap<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter = std::collections::btree_map::Iter<'a, K, V>;
    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}
impl<'a, K: Ord + Clone, V> IntoIterator for &'a mut DirtyMap<K, V> {
    type Item = (&'a K, &'a mut V);
    type IntoIter = std::collections::btree_map::IterMut<'a, K, V>;
    fn into_iter(self) -> Self::IntoIter {
        self.dirty.extend(self.entries.keys().cloned());
        self.entries.iter_mut()
    }
}
