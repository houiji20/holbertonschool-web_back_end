#!/usr/bin/env python3
"""
Annotated Function
"""
from typing import List, Iterable, Sequence, Tuple


def element_length(lst: Iterable[Sequence]) -> List[Tuple[Sequence, int]]:
    """
    AFunction that returns element length
    """
    return [(i, len(i)) for i in lst]
