// SPDX-License-Identifier: BSD-3-Clause

#include <unistd.h>
#include <sys/mman.h>
#include "osmem.h"
#include "block_meta.h"

#define METADATA_SIZE		(sizeof(struct block_meta))
#define PREALLOC		(128 * 1024 - METADATA_SIZE)
#define MMAP_THRESHOLD		(128 * 1024)
#define ALIGNMENT 8

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define MAP_SHARED	0x01
#define MAP_PRIVATE	0x02
#define MAP_ANONYMOUS	0x20
#define MAP_ANON	MAP_ANONYMOUS

#define MREMAP_MAYMOVE	1

#define MAP_FAILED	((void *) -1)

struct block_meta *block_meta_head;

void *os_malloc(size_t size)
{
	if (size <= 0)
		return NULL;
	if (size % ALIGNMENT != 0)
		size += ALIGNMENT - (size % 8);
	void *ptr = NULL;

	if (size + METADATA_SIZE < MMAP_THRESHOLD) {
		int verif = 1;
		struct block_meta *aux = block_meta_head;

		while (aux && verif == 1) {
			if (aux->status == 0 || aux->status == 1)
				verif = 0;
			aux = aux->next;
			if (aux == block_meta_head)
				break;
		}
		if (block_meta_head == NULL || verif == 1) {
			// Prealloc
			ptr = sbrk(MMAP_THRESHOLD);
			DIE(ptr == (void *)(-1), "eroare alocare");
			((struct block_meta *)ptr)->size = PREALLOC;
			((struct block_meta *)ptr)->status = 0;
			if (block_meta_head == NULL) {
				block_meta_head = (struct block_meta *)ptr;
				block_meta_head->next = block_meta_head;
				block_meta_head->prev = block_meta_head;
			} else {
				((struct block_meta *)ptr)->next = block_meta_head;
				((struct block_meta *)ptr)->prev = block_meta_head->prev;
				block_meta_head->prev->next = (struct block_meta *)ptr;
				block_meta_head->prev = (struct block_meta *)ptr;
			}
		}
		struct block_meta *current = block_meta_head;
		struct block_meta *last = block_meta_head;

		while (!(current->status == 0 && current->size >= size)) {
			last = current;
			current = current->next;
			if (current == block_meta_head)
				break;
		}
		if (current == block_meta_head && last->status == 0 && last->size < size) {
			// expand-block
			size_t add_new_size = 0;

			add_new_size = size - last->size;
			ptr = sbrk(add_new_size);
			DIE(ptr == (void *)(-1), "eroare alocare");
			last->size = size;
			last->status = 1;
			return (void *)last + METADATA_SIZE;
		} else if (current != NULL && current->status == 0 && current->size >= size) {
			// block-reuse
			if (current->size - size >= METADATA_SIZE + 1) {
				// split
				size_t new_block_dist = METADATA_SIZE + size;
				void *block = (void *)(current);
				((struct block_meta *)(block + new_block_dist))->prev = current;
				((struct block_meta *)(block + new_block_dist))->next = current->next;
				current->next->prev = (struct block_meta *)(block + new_block_dist);
				current->next = (struct block_meta *)(block + new_block_dist);
				((struct block_meta *)(block + new_block_dist))->status = 0;
				((struct block_meta *)(block + new_block_dist))->size = current->size - size - METADATA_SIZE;
				current->size = size;
			}
			current->status = 1;
			return (void *)current + METADATA_SIZE;
		} else if (current->status != 0) {
			ptr = sbrk(METADATA_SIZE + size);
			DIE(ptr == (void *)(-1), "eroare alocare");
			((struct block_meta *)ptr)->size = size;
			((struct block_meta *)ptr)->status = 1;
			((struct block_meta *)ptr)->next = block_meta_head;
			block_meta_head->prev = ((struct block_meta *)ptr);
			((struct block_meta *)ptr)->prev = last;
			last->next = ((struct block_meta *)ptr);
		}
	} else {
		struct block_meta *last = block_meta_head;

		if (block_meta_head == NULL) {
			ptr = mmap(NULL, size + METADATA_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
			DIE(ptr == MAP_FAILED, "eroare mapare");
			((struct block_meta *)ptr)->size = size;
			((struct block_meta *)ptr)->status = 2;
			block_meta_head = ((struct block_meta *)ptr);
			block_meta_head->next = block_meta_head;
			block_meta_head->prev = block_meta_head;
		} else {
			ptr = mmap(NULL, size + METADATA_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
			DIE(ptr == MAP_FAILED, "eroare mapare");
			((struct block_meta *)ptr)->size = size;
			((struct block_meta *)ptr)->status = 2;
			((struct block_meta *)ptr)->next = block_meta_head;
			block_meta_head->prev = ((struct block_meta *)ptr);
			((struct block_meta *)ptr)->prev = last;
			last->next = ((struct block_meta *)ptr);
		}
	}
	return ptr + METADATA_SIZE;
}

void os_free(void *ptr)
{
	if (ptr != NULL) {
		size_t size = 0;

		ptr = ptr - METADATA_SIZE;
		if (((struct block_meta *)ptr)->status != 2) {
			((struct block_meta *)ptr)->status = 0;
		} else {
			struct block_meta *block = ((struct block_meta *)ptr);

			size = block->size;
			if (block->next == block) {
				block->next = NULL;
				block->prev = NULL;
				block = NULL;
				block_meta_head = NULL;
			} else {
				block->prev->next = block->next;
				block->next->prev = block->prev;
				if (block_meta_head == block)
					block_meta_head = block->next;
			}
			munmap(ptr, size + METADATA_SIZE);
		}
		if (block_meta_head != NULL) {
			struct block_meta *current = block_meta_head;
			struct block_meta *last = block_meta_head;

			do {
				last = current;
				current = current->next;
				if (current != block_meta_head && last->status == 0) {
					while (current->status == 0 && current != block_meta_head) {
						last->size = last->size + current->size + METADATA_SIZE;
						last->next = current->next;
						current->next->prev = last;
						current = current->next;
					}
				}
			} while (current != block_meta_head);
		}
	}
}

void SetZero(void *ptr, size_t size)
{
	char *set_zero = (char *)ptr;

	for (unsigned int i = 0; i < size; i++)
		set_zero[i] = 0;
}

void *os_calloc(size_t nmemb, size_t size)
{
	size = size * nmemb;
	if (size <= 0)
		return NULL;
	if (size % ALIGNMENT != 0)
		size += ALIGNMENT - (size % 8);
	void *ptr = NULL;

	if (size + METADATA_SIZE < (unsigned int)(sysconf(_SC_PAGESIZE))) {
		int verif = 1;
		struct block_meta *aux = block_meta_head;

		while (aux && verif == 1) {
			if (aux->status == 0 || aux->status == 1)
				verif = 0;
			aux = aux->next;
			if (aux == block_meta_head)
				break;
		}
		if (block_meta_head == NULL || verif == 1) {
			// Prealloc
			ptr = sbrk(MMAP_THRESHOLD);
			DIE(ptr == (void *)(-1), "eroare alocare");
			SetZero(ptr + METADATA_SIZE, PREALLOC);
			((struct block_meta *)ptr)->size = PREALLOC;
			((struct block_meta *)ptr)->status = 0;
			if (block_meta_head == NULL) {
				block_meta_head = (struct block_meta *)ptr;
				block_meta_head->next = block_meta_head;
				block_meta_head->prev = block_meta_head;
			} else {
				((struct block_meta *)ptr)->next = block_meta_head;
				((struct block_meta *)ptr)->prev = block_meta_head->prev;
				block_meta_head->prev->next = (struct block_meta *)ptr;
			}
		}
		struct block_meta *current = block_meta_head;
		struct block_meta *last = block_meta_head;

		while (!(current->status == 0 && current->size >= size)) {
			last = current;
			current = current->next;
			if (current == block_meta_head)
				break;
		}
		if (current == block_meta_head && last->status == 0 && last->size < size) {
			// expand-block
			size_t add_new_size = 0;

			add_new_size = size - last->size;
			ptr = sbrk(add_new_size);
			DIE(ptr == (void *)(-1), "eroare alocare");
			SetZero((void *)last + METADATA_SIZE, size);
			last->size = size;
			last->status = 1;
			return (void *)last + METADATA_SIZE;
		} else if (current != NULL && current->status == 0 && current->size >= size) {
			// block-reuse
			if (current->size - size >= METADATA_SIZE + 8) {
				// split
				size_t new_block_dist = METADATA_SIZE + size;
				void *block = (void *)(current);
				((struct block_meta *)(block + new_block_dist))->prev = current;
				((struct block_meta *)(block + new_block_dist))->next = current->next;
				current->next->prev = (struct block_meta *)(block + new_block_dist);
				current->next = (struct block_meta *)(block + new_block_dist);
				((struct block_meta *)(block + new_block_dist))->status = 0;
				((struct block_meta *)(block + new_block_dist))->size = current->size - size - METADATA_SIZE;
				current->size = size;
			}
			SetZero((void *)current + METADATA_SIZE, current->size);
			current->status = 1;
			return (void *)current + METADATA_SIZE;
		} else if (current->status != 0) {
			ptr = sbrk(METADATA_SIZE + size);
			DIE(ptr == (void *)(-1), "eroare alocare");
			SetZero(ptr + METADATA_SIZE, size);
			((struct block_meta *)ptr)->size = size;
			((struct block_meta *)ptr)->status = 1;
			((struct block_meta *)ptr)->next = block_meta_head;
			block_meta_head->prev = ((struct block_meta *)ptr);
			((struct block_meta *)ptr)->prev = last;
			last->next = ((struct block_meta *)ptr);
		}
	} else {
		struct block_meta *last = block_meta_head;

		if (block_meta_head == NULL) {
			ptr = mmap(NULL, size + METADATA_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
			DIE(ptr == MAP_FAILED, "eroare mapare");
			SetZero(ptr + METADATA_SIZE, size);
			((struct block_meta *)ptr)->size = size;
			((struct block_meta *)ptr)->status = 2;
			block_meta_head = ((struct block_meta *)ptr);
			block_meta_head->next = block_meta_head;
			block_meta_head->prev = block_meta_head;
		} else {
			ptr = mmap(NULL, size + METADATA_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
			DIE(ptr == MAP_FAILED, "eroare mapare");
			SetZero(ptr + METADATA_SIZE, size);
			((struct block_meta *)ptr)->size = size;
			((struct block_meta *)ptr)->status = 2;
			((struct block_meta *)ptr)->next = block_meta_head;
			block_meta_head->prev = ((struct block_meta *)ptr);
			((struct block_meta *)ptr)->prev = last;
			last->next = ((struct block_meta *)ptr);
		}
	}
	return ptr + METADATA_SIZE;
}

void CopyContent(void *ptr1, void *ptr2, size_t size)
{
	char *dest = (char *)ptr1;
	char *sursa = (char *)ptr2;

	for (unsigned int i = 0; i < size; i++)
		dest[i] = sursa[i];
}

size_t minim(size_t a, size_t b)
{
	if (a < b)
		return a;
	return b;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	if (ptr == NULL)
		return os_malloc(size);
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}
	void *adr = NULL;

	if (size % ALIGNMENT != 0)
		size += ALIGNMENT - (size % 8);
	ptr = ptr - METADATA_SIZE;
	struct block_meta *block = (struct block_meta *)ptr;

	if (((struct block_meta *)ptr)->status == 0)
		return NULL;
	if (((struct block_meta *)ptr)->status == 1) {
		if (size <= block->size) {
			if (block->size - size >= METADATA_SIZE + 1) {
				// split
				size_t new_block_dist = METADATA_SIZE + size;
				void *new_block = (void *)(block);
				((struct block_meta *)(new_block + new_block_dist))->prev = block;
				((struct block_meta *)(new_block + new_block_dist))->next = block->next;
				block->next->prev = (struct block_meta *)(new_block + new_block_dist);
				block->next = (struct block_meta *)(new_block + new_block_dist);
				((struct block_meta *)(new_block + new_block_dist))->status = 0;
				((struct block_meta *)(new_block + new_block_dist))->size = block->size - size - METADATA_SIZE;
				block->size = size;
			}
			block->status = 1;
			return (void *)block + METADATA_SIZE;
		} else if (block->next->status == 0) {
			size_t old_size = block->size;

			block->status = 0;
			while (block->next->status == 0 && block->next != block_meta_head) {
				size_t new_size = block->next->size + METADATA_SIZE;

				block->next = block->next->next;
				block->next->next->prev = block;
				block->size = block->size + new_size;
				if (block->size >= size) {
					block->status = 1;
					break;
				}
			}
			if (block->status == 1) {
				if (block->size - size >= METADATA_SIZE + 1) {
					// split
					size_t new_block_dist = METADATA_SIZE + size;
					void *new_block = (void *)(block);
					((struct block_meta *)(new_block + new_block_dist))->prev = block;
					((struct block_meta *)(new_block + new_block_dist))->next = block->next;
					block->next->prev = (struct block_meta *)(new_block + new_block_dist);
					block->next = (struct block_meta *)(new_block + new_block_dist);
					((struct block_meta *)(new_block + new_block_dist))->status = 0;
					((struct block_meta *)(new_block + new_block_dist))->size = block->size - size - METADATA_SIZE;
					block->size = size;
				}
				return (void *)block + METADATA_SIZE;
			}
			block->status = 0;
			adr = os_malloc(size);
			CopyContent(adr, ptr + METADATA_SIZE, old_size);
		} else {
			size_t old_size = block->size;

			block->status = 0;
			adr = os_malloc(size);
			CopyContent(adr, ptr + METADATA_SIZE, old_size);
		}
	} else {
		size_t old_size = block->size;

		adr = os_malloc(size);
		CopyContent(adr, ptr + METADATA_SIZE, minim(size, old_size));
		os_free(ptr + METADATA_SIZE);
	}
	return adr;
}
