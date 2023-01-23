#!/usr/bin/env python3
"""
sum_mixed_list which takes a list
mxd_lst of integers and floats and returns their sum as a float.
"""
from typing import List, Union


def sum_mixed_list(mxd_lst: List[Union[int, float]]) -> float:
    """
    returns sum of list elements
    """
    total: int = 0
    for i in mxd_lst:
        total += i
    return total
