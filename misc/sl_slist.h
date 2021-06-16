/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - single link list
 * @version 3.2.0
 *******************************************************************************
 * # License
 * <b>Copyright 2021 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of Silicon Labs Master Software License
 * Agreement (MSLA) available at
 * www.silabs.com/about-us/legal/master-software-license-agreement. This
 * software is distributed to you in Source Code format and is governed by the
 * sections of the MSLA applicable to Source Code.
 *
 ******************************************************************************/

#ifndef SL_SLIST_H
#define SL_SLIST_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
 * @addtogroup slist Singly-Linked List
 * @brief Singly-linked list
 * @{
 ******************************************************************************/

/// List node type
typedef struct sl_slist_node sl_slist_node_t;

/// List node
struct sl_slist_node {
  sl_slist_node_t *node; ///< List node
};

#ifndef DOXYGEN
#define  container_of(ptr, type, member)  (type *)((uintptr_t)(ptr) - ((uintptr_t)(&((type *)0)->member)))

#define  SL_SLIST_ENTRY                               container_of

#define  SL_SLIST_FOR_EACH(list_head, iterator)       for ((iterator) = (list_head); (iterator) != NULL; (iterator) = (iterator)->node)

#define  SL_SLIST_FOR_EACH_ENTRY(list_head, entry, type, member) for (  (entry) = SL_SLIST_ENTRY(list_head, type, member); \
                                                                        (entry) != SL_SLIST_ENTRY(NULL, type, member);     \
                                                                        (entry) = SL_SLIST_ENTRY((entry)->member.node, type, member))
#ifdef __GNUC__
#define  SL_SLIST_FOR_EACH_ENTRY_T(list_head, entry, member) SL_SLIST_FOR_EACH_ENTRY(list_head, entry, typeof(*entry), member)
#endif

#endif

// -----------------------------------------------------------------------------
// Prototypes

/*******************************************************************************
 * Initialize a singly-linked list.
 *
 * @param    head  Pointer to pointer of head element of list.
 ******************************************************************************/
void sl_slist_init(sl_slist_node_t **head);

/*******************************************************************************
 * Return number of item in the list.
 *
 * @param    head  Pointer to pointer of head element of list.
 ******************************************************************************/
unsigned int sl_slist_len(sl_slist_node_t **head);

/*******************************************************************************
 * Add given item at beginning of the list.
 *
 * @param    head  Pointer to pointer of head element of the list.
 *
 * @param    item  Pointer to an item to add.
 ******************************************************************************/
void sl_slist_push(sl_slist_node_t **head,
                   sl_slist_node_t *item);

/*******************************************************************************
 * Add item at the end of the list.
 *
 * @param    head  Pointer to the pointer of a head element of the list.
 *
 * @param    item  Pointer to the item to add.
 ******************************************************************************/
void sl_slist_push_back(sl_slist_node_t **head,
                        sl_slist_node_t *item);

/*******************************************************************************
 * Remove and return the first element of the list.
 *
 * @param    head  Pointer to he pointer of the head element of the list.
 *
 * @return   Pointer to item that was at top of the list.
 ******************************************************************************/
sl_slist_node_t *sl_slist_pop(sl_slist_node_t **head);

/*******************************************************************************
 * Insert an item after the given item.
 *
 * @param    item  Pointer to an item to add.
 *
 * @param    pos   Pointer to an item after which the item to add will be inserted.
 ******************************************************************************/
void sl_slist_insert(sl_slist_node_t *item,
                     sl_slist_node_t *pos);

/*******************************************************************************
 * Remove an item from the list.
 *
 * @param    head  Pointer to pointer of the head element of list.
 *
 * @param    item  Pointer to the item to remove.
 *
 * @note     (1) An EFM_ASSERT is thrown if the item is not found within the list.
 ******************************************************************************/
void sl_slist_remove(sl_slist_node_t **head,
                     sl_slist_node_t *item);

/*******************************************************************************
 * Sort list items.
 *
 * @param    head      Pointer to the pointer of the head element of the list.
 *
 * @param    cmp_fnct  Pointer to function to use for sorting the list.
 *                     item_l    Pointer to left  item.
 *                     item_r    Pointer to right item.
 *                     Returns whether the two items are ordered (true) or not (false).
 ******************************************************************************/
void sl_slist_sort(sl_slist_node_t **head,
                   bool (*cmp_fnct)(sl_slist_node_t *item_l,
                                    sl_slist_node_t *item_r));

/** @} (end addtogroup slist) */

#ifdef __cplusplus
}
#endif

#endif /* SL_SLIST_H */
