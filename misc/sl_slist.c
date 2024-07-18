/***************************************************************************//**
 * @file
 * @brief Co-Processor Communication Protocol(CPC) - single link list
 *******************************************************************************
 * # License
 * <b>Copyright 2022 Silicon Laboratories Inc. www.silabs.com</b>
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

#include "config.h"

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#include "cpcd/sl_slist.h"

#define EFM_ASSERT(cond) assert(cond)

/*******************************************************************************
 **************************   GLOBAL FUNCTIONS   *******************************
 ******************************************************************************/

/***************************************************************************//**
 * Initializes a singly-linked list.
 ******************************************************************************/
void sl_slist_init(sl_slist_node_t **head)
{
  *head = 0;
}

/***************************************************************************//**
 * Return number of elements in the list.
 ******************************************************************************/
unsigned int sl_slist_len(sl_slist_node_t **head)
{
  sl_slist_node_t *it;
  unsigned int count = 0;

  EFM_ASSERT(head != NULL);

  for (it = *head; it != NULL; it = it->node) {
    count++;
  }

  return count;
}

/***************************************************************************//**
 * Add given item at beginning of list.
 ******************************************************************************/
void sl_slist_push(sl_slist_node_t **head,
                   sl_slist_node_t *item)
{
  EFM_ASSERT((item != NULL)
             && (head != NULL));

  item->node = *head;
  *head = item;
}

/***************************************************************************//**
 * Add item at end of list.
 ******************************************************************************/
void sl_slist_push_back(sl_slist_node_t **head,
                        sl_slist_node_t *item)
{
  sl_slist_node_t **node_ptr = head;

  EFM_ASSERT((item != NULL)
             && (head != NULL));

  while (*node_ptr != NULL) {
    node_ptr = &((*node_ptr)->node);
  }

  item->node = NULL;
  *node_ptr = item;
}

/***************************************************************************//**
 * Removes and returns first element of list.
 ******************************************************************************/
sl_slist_node_t *sl_slist_pop(sl_slist_node_t **head)
{
  sl_slist_node_t *item;

  EFM_ASSERT(head != NULL);

  item = *head;
  if (item == NULL) {
    return (NULL);
  }

  *head = item->node;

  item->node = NULL;

  return (item);
}

/***************************************************************************//**
 * Insert item after given item.
 ******************************************************************************/
void sl_slist_insert(sl_slist_node_t *item,
                     sl_slist_node_t *pos)
{
  EFM_ASSERT((item != NULL)
             && (pos != NULL));

  item->node = pos->node;
  pos->node = item;
}

/***************************************************************************//**
 * Remove item from list.
 ******************************************************************************/
void sl_slist_remove(sl_slist_node_t **head,
                     sl_slist_node_t *item)
{
  sl_slist_node_t **node_ptr;

  EFM_ASSERT((item != NULL)
             && (head != NULL));

  for (node_ptr = head; *node_ptr != NULL; node_ptr = &((*node_ptr)->node)) {
    if (*node_ptr == item) {
      *node_ptr = item->node;
      return;
    }
  }
}

/***************************************************************************//**
 * Sorts list items.
 ******************************************************************************/
void sl_slist_sort(sl_slist_node_t **head,
                   bool (*cmp_fnct)(sl_slist_node_t *item_l,
                                    sl_slist_node_t *item_r))
{
  bool  swapped;
  sl_slist_node_t **pp_item_l;

  EFM_ASSERT((head != NULL)
             && (cmp_fnct != NULL));

  do {
    swapped = false;

    pp_item_l = head;
    // Loop until end of list is found.
    while ((*pp_item_l != NULL) && ((*pp_item_l)->node != NULL)) {
      sl_slist_node_t *p_item_r = (*pp_item_l)->node;
      bool  ordered;

      // Call provided compare fnct.
      ordered = cmp_fnct(*pp_item_l, p_item_r);
      if (ordered == false) {
        // If order is not correct, swap items.
        sl_slist_node_t *p_tmp = p_item_r->node;

        // Swap the two items.
        p_item_r->node = *pp_item_l;
        (*pp_item_l)->node = p_tmp;
        *pp_item_l = p_item_r;
        pp_item_l = &(p_item_r->node);
        // Indicate a swap has been done.
        swapped = true;
      } else {
        pp_item_l = &((*pp_item_l)->node);
      }
    }
    // Re-loop until no items have been swapped.
  } while (swapped == true);
}
