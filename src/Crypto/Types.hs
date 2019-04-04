module Crypto.Types where

import           Crypto.Hash (Digest, SHA256)


type Tx = Digest SHA256


data MerkleTree a
  = Leaf
  | Node a (MerkleTree a) (MerkleTree a)
  deriving (Eq, Show)


instance Functor MerkleTree where
  fmap _ Leaf         = Leaf
  fmap f (Node x l r) = Node (f x) (fmap f l) (fmap f r)
