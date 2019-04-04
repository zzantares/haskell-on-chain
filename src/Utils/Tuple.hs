module Utils.Tuple where


elem :: Eq a => a -> (a, a) -> Bool
elem x (a, b) = x == a || x == b
