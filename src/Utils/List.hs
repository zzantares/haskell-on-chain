module Utils.List where


-- | Groups by two the adjancent elements in a list starting from the left. If
-- the list is odd length the last element is grouped with itself.
byTwo :: [a] -> [(a, a)]
byTwo []           = []
byTwo [x]          = [(x, x)]
byTwo (x : y : zs) = (x, y) : byTwo zs
