use bumpalo::Bump;
use std::cell::RefCell;
// Arena allocator - no direct source location import needed

/// Arena allocator for AST nodes, providing efficient memory management
#[derive(Debug)]
pub struct AstArena {
    pub bump: Bump,
    source_files: RefCell<Vec<String>>,
}

impl AstArena {
    /// Create a new AST arena
    pub fn new() -> Self {
        Self {
            bump: Bump::new(),
            source_files: RefCell::new(Vec::new()),
        }
    }

    /// Allocate a value in the arena and return a reference with arena lifetime
    pub fn alloc<T>(&self, value: T) -> &T {
        self.bump.alloc(value)
    }

    /// Allocate a slice in the arena
    pub fn alloc_slice<T>(&self, slice: &[T]) -> &[T]
    where
        T: Clone,
    {
        self.bump.alloc_slice_clone(slice)
    }

    /// Allocate a string in the arena
    pub fn alloc_str(&self, s: &str) -> &str {
        self.bump.alloc_str(s)
    }

    /// Add a source file and return its index
    pub fn add_source_file(&self, content: String) -> usize {
        let mut files = self.source_files.borrow_mut();
        let index = files.len();
        files.push(content);
        index
    }

    /// Get source file content by index
    pub fn get_source_file(&self, index: usize) -> Option<String> {
        self.source_files.borrow().get(index).cloned()
    }

    /// Get the number of allocated bytes
    pub fn allocated_bytes(&self) -> usize {
        self.bump.allocated_bytes()
    }

    /// Reset the arena, deallocating all memory
    pub fn reset(&mut self) {
        self.bump.reset();
        self.source_files.borrow_mut().clear();
    }
}

impl Default for AstArena {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for types that can be allocated in the AST arena
pub trait ArenaAllocated<'arena> {
    /// Allocate this value in the given arena
    fn alloc_in(self, arena: &'arena AstArena) -> &'arena Self;
}

impl<'arena, T> ArenaAllocated<'arena> for T {
    fn alloc_in(self, arena: &'arena AstArena) -> &'arena Self {
        arena.alloc(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arena_allocation() {
        let arena = AstArena::new();

        let value = arena.alloc(42u32);
        assert_eq!(*value, 42);

        let string = arena.alloc_str("test");
        assert_eq!(string, "test");
    }

    #[test]
    fn test_arena_slice_allocation() {
        let arena = AstArena::new();

        let slice = arena.alloc_slice(&[1, 2, 3, 4, 5]);
        assert_eq!(slice, &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_source_file_management() {
        let arena = AstArena::new();

        let index1 = arena.add_source_file("contract Test1 {}".to_string());
        let index2 = arena.add_source_file("contract Test2 {}".to_string());

        assert_eq!(index1, 0);
        assert_eq!(index2, 1);

        assert_eq!(arena.get_source_file(0), Some("contract Test1 {}".to_string()));
        assert_eq!(arena.get_source_file(1), Some("contract Test2 {}".to_string()));
        assert_eq!(arena.get_source_file(2), None);
    }
}