import numpy as np
from cipher.classical import rail_fence_order


def rail_inverse(c: np.ndarray, rails: int) -> np.ndarray:
    """Undo the Rail Fence stage for a guessed depth (array version)."""
    order = np.asarray(rail_fence_order(len(c), rails), dtype=np.int64)
    v = np.empty_like(c)
    v[order] = c
    return v


def vig_decrypt(v: np.ndarray, key: np.ndarray) -> np.ndarray:
    L = len(key)
    reps = -(-len(v) // L)
    return (v - np.tile(key, reps)[:len(v)]) % 26
