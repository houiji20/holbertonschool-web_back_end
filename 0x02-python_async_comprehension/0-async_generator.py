#!/usr/bin/env python3
"""
asynchronously wait 1 second, then yield a random number
between 0 and 10. Use the random module.
"""
import asyncio
import random
from typing import Generator


async def async_generator() -> Generator[float, None, None]:
    """
    collect 10 random numbers using
    async_generator
    """
    for i in range(10):
        await asyncio.sleep(1)
        yield random.uniform(0, 10)
