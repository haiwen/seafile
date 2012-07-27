/*****************************************************************************

    avl.h - Source code for the AVL-tree library.

    Copyright (C) 1998  Michael H. Buselli <cosine@cosine.org>
    Copyright (C) 2000-2002  Wessel Dankers <wsl@nl.linux.org>

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA

    Augmented AVL-tree. Original by Michael H. Buselli <cosine@cosine.org>.

    Modified by Wessel Dankers <wsl@nl.linux.org> to add a bunch of bloat to
    the sourcecode, change the interface and squash a few bugs.
    Mail him if you find new bugs.

*****************************************************************************/

#ifndef _AVL_H
#define _AVL_H

/* We need either depths, counts or both (the latter being the default) */
#if !defined(AVL_DEPTH) && !defined(AVL_COUNT)
#define AVL_DEPTH
#define AVL_COUNT
#endif

/* User supplied function to compare two items like strcmp() does.
 * For example: cmp(a,b) will return:
 *   -1  if a < b
 *    0  if a = b
 *    1  if a > b
 */
typedef int (*avl_compare_t)(const void *, const void *);

/* User supplied function to delete an item when a node is free()d.
 * If NULL, the item is not free()d.
 */
typedef void (*avl_freeitem_t)(void *);

typedef struct avl_node_t {
	struct avl_node_t *next;
	struct avl_node_t *prev;
	struct avl_node_t *parent;
	struct avl_node_t *left;
	struct avl_node_t *right;
	void *item;
#ifdef AVL_COUNT
	unsigned int count;
#endif
#ifdef AVL_DEPTH
	unsigned char depth;
#endif
} avl_node_t;

typedef struct avl_tree_t {
	avl_node_t *head;
	avl_node_t *tail;
	avl_node_t *top;
	avl_compare_t cmp;
	avl_freeitem_t freeitem;
} avl_tree_t;

/* Initializes a new tree for elements that will be ordered using
 * the supplied strcmp()-like function.
 * Returns the value of avltree (even if it's NULL).
 * O(1) */
extern avl_tree_t *avl_init_tree(avl_tree_t *avltree, avl_compare_t, avl_freeitem_t);

/* Allocates and initializes a new tree for elements that will be
 * ordered using the supplied strcmp()-like function.
 * Returns NULL if memory could not be allocated.
 * O(1) */
extern avl_tree_t *avl_alloc_tree(avl_compare_t, avl_freeitem_t);

/* Frees the entire tree efficiently. Nodes will be free()d.
 * If the tree's freeitem is not NULL it will be invoked on every item.
 * O(n) */
extern void avl_free_tree(avl_tree_t *);

/* Reinitializes the tree structure for reuse. Nothing is free()d.
 * Compare and freeitem functions are left alone.
 * O(1) */
extern void avl_clear_tree(avl_tree_t *);

/* Free()s all nodes in the tree but leaves the tree itself.
 * If the tree's freeitem is not NULL it will be invoked on every item.
 * O(n) */
extern void avl_free_nodes(avl_tree_t *);

/* Initializes memory for use as a node. Returns NULL if avlnode is NULL.
 * O(1) */
extern avl_node_t *avl_init_node(avl_node_t *avlnode, void *item);

/* Insert an item into the tree and return the new node.
 * Returns NULL and sets errno if memory for the new node could not be
 * allocated or if the node is already in the tree (EEXIST).
 * O(lg n) */
extern avl_node_t *avl_insert(avl_tree_t *, void *item);

/* Insert a node into the tree and return it.
 * Returns NULL if the node is already in the tree.
 * O(lg n) */
extern avl_node_t *avl_insert_node(avl_tree_t *, avl_node_t *);

/* Insert a node in an empty tree. If avlnode is NULL, the tree will be
 * cleared and ready for re-use.
 * If the tree is not empty, the old nodes are left dangling.
 * O(1) */
extern avl_node_t *avl_insert_top(avl_tree_t *, avl_node_t *avlnode);

/* Insert a node before another node. Returns the new node.
 * If old is NULL, the item is appended to the tree.
 * O(lg n) */
extern avl_node_t *avl_insert_before(avl_tree_t *, avl_node_t *old, avl_node_t *new);

/* Insert a node after another node. Returns the new node.
 * If old is NULL, the item is prepended to the tree.
 * O(lg n) */
extern avl_node_t *avl_insert_after(avl_tree_t *, avl_node_t *old, avl_node_t *new);

/* Deletes a node from the tree. Returns immediately if the node is NULL.
 * The item will not be free()d regardless of the tree's freeitem handler.
 * This function comes in handy if you need to update the search key.
 * O(lg n) */
extern void avl_unlink_node(avl_tree_t *, avl_node_t *);

/* Deletes a node from the tree. Returns immediately if the node is NULL.
 * If the tree's freeitem is not NULL, it is invoked on the item.
 * If it is, returns the item.
 * O(lg n) */
extern void *avl_delete_node(avl_tree_t *, avl_node_t *);

/* Searches for an item in the tree and deletes it if found.
 * If the tree's freeitem is not NULL, it is invoked on the item.
 * If it is, returns the item.
 * O(lg n) */
extern void *avl_delete(avl_tree_t *, const void *item);

/* If exactly one node is moved in memory, this will fix the pointers
 * in the tree that refer to it. It must be an exact shallow copy.
 * Returns the pointer to the old position.
 * O(1) */
extern avl_node_t *avl_fixup_node(avl_tree_t *, avl_node_t *new);

/* Searches for a node with the key closest (or equal) to the given item.
 * If avlnode is not NULL, *avlnode will be set to the node found or NULL
 * if the tree is empty. Return values:
 *   -1  if the returned node is smaller
 *    0  if the returned node is equal or if the tree is empty
 *    1  if the returned node is greater
 * O(lg n) */
extern int avl_search_closest(const avl_tree_t *, const void *item, avl_node_t **avlnode);

/* Searches for the item in the tree and returns a matching node if found
 * or NULL if not.
 * O(lg n) */
extern avl_node_t *avl_search(const avl_tree_t *, const void *item);

#ifdef AVL_COUNT
/* Returns the number of nodes in the tree.
 * O(1) */
extern unsigned int avl_count(const avl_tree_t *);

/* Searches a node by its rank in the list. Counting starts at 0.
 * Returns NULL if the index exceeds the number of nodes in the tree.
 * O(lg n) */
extern avl_node_t *avl_at(const avl_tree_t *, unsigned int);

/* Returns the rank of a node in the list. Counting starts at 0.
 * O(lg n) */
extern unsigned int avl_index(const avl_node_t *);
#endif

#endif
