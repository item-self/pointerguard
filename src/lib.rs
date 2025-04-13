use std::fmt;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::time::{SystemTime, UNIX_EPOCH};

trait Encrypt {
    fn encrypt(&self, data: u64, key: u64) -> u64;
    fn decrypt(&self, data: u64, key: u64) -> u64;
}

/// An encrypted pointer that decrypts when dereferenced.
pub struct EncryptedPtr<T> {
    encrypted_ptr: u64,
    key: u64,
    method: Box<dyn Encrypt>,
    _marker: PhantomData<*mut T>,
}

impl<T> EncryptedPtr<T> {
    /// Generate a random key using the current time.
    #[inline(always)]
    pub fn generate_key() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as _
    }

    /// Create a new encrypted pointer from a raw pointer
    #[inline(always)]
    pub fn new(ptr: *mut T) -> Self {
        // generate a random key, maybe let user decide.
        let key = Self::generate_key();

        // here we have a list of all possible encryption methods.
        let mut methods: Vec<Box<dyn Encrypt>> =
            vec![Box::new(MethodA), Box::new(MethodB), Box::new(MethodC)];

        // choose a random method to encrypt the pointer with.
        let method = methods.remove(rand::random_range(0..methods.len()));

        // encrypt the pointer.
        let encrypted_ptr = method.encrypt(ptr as u64, key);

        Self {
            encrypted_ptr,
            key,
            method,
            _marker: PhantomData,
        }
    }

    /// Get the raw pointer by decrypting.
    #[inline(always)]
    fn decrypt_ptr(&self) -> *mut T {
        // decrypt the pointer.
        let ptr_val = self.method.decrypt(self.encrypted_ptr, self.key);
        ptr_val as *mut T
    }
}

impl<T> Deref for EncryptedPtr<T> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        // here's where the decryption actually happens on each access.
        let ptr = self.decrypt_ptr();

        unsafe { &*ptr }
    }
}

impl<T> DerefMut for EncryptedPtr<T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        // Decrypt on mutable access as well
        let ptr = self.decrypt_ptr();
        unsafe { &mut *ptr }
    }
}

impl<T> Drop for EncryptedPtr<T> {
    #[inline(always)]
    fn drop(&mut self) {
        // decrypt the pointer.
        let ptr = self.decrypt_ptr();

        unsafe {
            // drop the T from the pointer.
            std::ptr::drop_in_place(ptr);
            // deallocate the T from the pointer.
            std::alloc::dealloc(ptr as *mut u8, std::alloc::Layout::new::<T>());
        }
    }
}

impl<T> From<Box<T>> for EncryptedPtr<T> {
    fn from(value: Box<T>) -> Self {
        Self::new(Box::into_raw(value))
    }
}

impl<T: fmt::Debug> fmt::Debug for EncryptedPtr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedPtr")
            .field("encrypted_value", &format!("{:#x}", self.encrypted_ptr))
            .field("pointed_value", &self.deref())
            .finish()
    }
}

struct MethodA;
impl Encrypt for MethodA {
    #[inline(always)]
    fn encrypt(&self, mut data: u64, key: u64) -> u64 {
        data ^= key;
        data = data.rotate_left((key & 0xF) as u32);
        data ^= key << 3;
        data = data.rotate_left(7);
        data ^= key.rotate_left(11);
        data
    }

    #[inline(always)]
    fn decrypt(&self, mut data: u64, key: u64) -> u64 {
        // Reverse operations in opposite order
        data ^= key.rotate_left(11);
        data = data.rotate_right(7);
        data ^= key << 3;
        data = data.rotate_right((key & 0xF) as u32);
        data ^= key;
        data
    }
}

struct MethodB;
impl Encrypt for MethodB {
    #[inline(always)]
    fn encrypt(&self, mut data: u64, key: u64) -> u64 {
        data ^= key;
        data = data.rotate_left(13);
        data ^= key.rotate_left(5);
        data = data.rotate_left(9);
        data ^= key.rotate_left(17);
        data
    }

    #[inline(always)]
    fn decrypt(&self, mut data: u64, key: u64) -> u64 {
        data ^= key.rotate_left(17);
        data = data.rotate_right(9);
        data ^= key.rotate_left(5);
        data = data.rotate_right(13);
        data ^= key;
        data
    }
}

struct MethodC;
impl Encrypt for MethodC {
    #[inline(always)]
    fn encrypt(&self, mut data: u64, key: u64) -> u64 {
        data ^= key;
        let upper = key >> 32;
        let lower = key & 0xFFFFFFFF;
        data ^= ((upper) << 32) | (lower);
        data = data.rotate_left((key % 31) as u32);
        data ^= key ^ (key >> 11);
        data
    }

    #[inline(always)]
    fn decrypt(&self, mut data: u64, key: u64) -> u64 {
        data ^= key ^ (key >> 11);
        data = data.rotate_right((key % 31) as u32);
        let upper = key >> 32;
        let lower = key & 0xFFFFFFFF;
        data ^= ((upper) << 32) | (lower);
        data ^= key;
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn decrypt_ptr_box() {
        /// Example player struct.
        struct Player {
            health: u32,
        }

        // turn box into encrypted pointer.
        let player: EncryptedPtr<_> = Box::new(Player { health: 100 }).into();

        assert_eq!(player.health, 100);
    }

    #[test]
    fn decrypt_value_a() {
        let key: u64 = 0x1234567890ABCDEF;
        let data: u64 = 0xFEDCBA0987654321;

        // create test object.
        let a = MethodA;

        let encrypted = a.encrypt(data, key);
        let decrypted = a.decrypt(encrypted, key);

        assert_eq!(data, decrypted);
    }

    #[test]
    fn decrypt_value_b() {
        let key: u64 = 0x1234567890ABCDEF;
        let data: u64 = 0xFEDCBA0987654321;

        // create test object.
        let b = MethodB;

        let encrypted = b.encrypt(data, key);
        let decrypted = b.decrypt(encrypted, key);

        assert_eq!(data, decrypted);
    }

    #[test]
    fn decrypt_value_c() {
        let key: u64 = 0x1234567890ABCDEF;
        let data: u64 = 0xFEDCBA0987654321;

        // create test object.
        let c = MethodC;

        let encrypted = c.encrypt(data, key);
        let decrypted = c.decrypt(encrypted, key);

        assert_eq!(data, decrypted);
    }
}
