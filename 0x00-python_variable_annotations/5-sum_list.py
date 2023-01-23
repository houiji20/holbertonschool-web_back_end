#!/usr/bin/env python3
"""
sum_list which takes a list input_list of
floats as argument and returns their sum as a float.
"""
from typing import List


def sum_list(input_list: List[float]) -> float:
    """
    sum function
    """
    total: int = 0
    for i in input_list:
        total += i
    return total
