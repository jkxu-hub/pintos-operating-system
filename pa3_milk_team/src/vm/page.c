#include "page.h"

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page(void *upage, void *kpage, bool writable)
{
    struct thread *t = thread_current();

    /* Verify that there's not already a page at that virtual
     address, then map our page there. */
    return (pagedir_get_page(t->pagedir, upage) == NULL && pagedir_set_page(t->pagedir, upage, kpage, writable));
}

/**
Looks within the current thread's page table to see if it has an entry
that corresponds to the passed in address. This is a quick 'lookup' in our hash table
that serves as our table. If there is no page that this thread has that
has the desired address, then we return NULL.
 */
struct supplemental_page_table_entry *get_page_entry(uint8_t *addr)
{
    // TODO: IMPLEMENT PLACEMENT OF THIS ALLOCATED PAGE WITHIN THE SUPPLEMENTAL PAGE TABLE
    //struct hash_elem *hash_find (struct hash *, struct hash_elem *);

    struct supplemental_page_table_entry p;
    struct hash_elem *e;

    p.user_page_addr = addr;
    e = hash_find(&thread_current() -> sup_page_table, &p.page_elem);
    return e!= NULL ? hash_entry(e, struct supplemental_page_table_entry, page_elem) : NULL;
}

/**
First checks to see if a page with this user address already exists. If not, create one.
Makes a page table entry with its info populated with the passed-in
parameters. See the definitions of the file and off_t types.

ofs is the pointer offset to the beginning the of data to be read from this page.
upage is the virtual address associated with this page.
read_bytes is the amount of bytes of data in this page that should be read if we fetch data from this page.
zero_bytes is the amount of bytes within the page to zero if a zero-ed out page is requested.
bool writable indicates whether or not this page can have its contents overwritten.

Puts the entry into the supplemental page table for the thread who wanted it.
Returns the address of the entry itself or NULL if failure.
 */
struct supplemental_page_table_entry *create_page(struct file *file, off_t ofs, uint8_t *upage,
                                                  uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{

    struct supplemental_page_table_entry *pg_entry = malloc(sizeof(struct supplemental_page_table_entry));
    if (get_page_entry(upage) == NULL && pg_entry != NULL)
    {
        pg_entry->file = file;
        pg_entry->offset = ofs;
        pg_entry->read_bytes = read_bytes;
        pg_entry->zero_bytes = zero_bytes;
        pg_entry->writable = writable;
        pg_entry->user_page_addr = upage;

        // TODO: IMPLEMENT PLACEMENT OF THIS ALLOCATED PAGE WITHIN THE PAGE TABLE
        hash_insert(&thread_current() -> sup_page_table, &(pg_entry ->page_elem));

        return pg_entry;
    }

    free(pg_entry);
    return NULL;
}

/**
 This function should be filled out to be called when a user program needs
 another page allocated for its stack.

 It takes in the address that the process has attempted to use and should
 return a boolean indicating its success as true or failure as false.
 */
bool expand_stack_memory(void *upage)
{
    //struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable)
    // TODO: IMPLEMENT AS SPECIFIED IN PROJECT HANDOUT AND ABOVE FUNCTION COMMENT
    struct supplemental_page_table_entry *rpage =  create_page(NULL, 0, upage, 0, PGSIZE, true);
   //this struct might still need some work on it, in that there are more parameters to follow
    if(!load_from_file(rpage)){
        return false;
    }
    else{
        return true;
    }

    
}

/**
Loads data from a page into a frame. The page entry structure contains data that tells us
where its data starts within the page pointer (the offset) and how much data needs to be read
from the page to retrieve it all (read_bytes). Clears the space within the frame to make sure
that no residual data is left over from an evicted page or uninitialized space. Then loads
the page data into the frame, completing the page installation into a frame.
 */
bool load_from_file(struct supplemental_page_table_entry *pg_entry)
{
    if (pg_entry != NULL)
    {
        struct frame_table_entry *frame = allocate_frame(pg_entry);
        if (frame != NULL)
        {
            if (pg_entry->read_bytes != 0)
            {
                uint32_t read_bytes = file_read_at(pg_entry->file, frame->frame_addr, pg_entry->read_bytes, pg_entry->offset);
                if (read_bytes != pg_entry->read_bytes)
                {
                    remove_frame(frame);
                    return false;
                }
            }

            memset(frame->frame_addr + pg_entry->read_bytes, 0, pg_entry->zero_bytes);
            if (!install_page(pg_entry->user_page_addr, frame->frame_addr, pg_entry->writable))
            {
                remove_frame(frame);
                return false;
            }
        }
    }

    return true;
}

/**
Removes the indicated entry from the current thread's page table and gives the memory
used by malloc back to the kernel.
 */
void remove_page_entry(struct supplemental_page_table_entry *pg_entry)
{
    // TODO: IMPLEMENT REMOVAL OF THE SPECIFIED PAGE WITHIN THE PAGE TABLE

    free(pg_entry);
}

/*Student Code: */
/*
hash_hash_func for supplemental page table 
Returns a hash value for page p.*/
unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct supplemental_page_table_entry *p = hash_entry (p_, struct supplemental_page_table_entry, page_elem);

  return hash_bytes (&p->user_page_addr, sizeof p->user_page_addr);
}

/*
hash_less_func for supplemental page table 
Returns true if page a precedes page b.*/
bool
page_less (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED)
{
  const struct supplemental_page_table_entry *a = hash_entry (a_, struct supplemental_page_table_entry, page_elem);
  const struct supplemental_page_table_entry *b = hash_entry (b_, struct supplemental_page_table_entry, page_elem);

  return a->user_page_addr < b->user_page_addr;
}