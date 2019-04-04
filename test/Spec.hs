module Main where

import           Crypto.MerkleSpec (merkleSpec)
import           Test.Hspec
import           Utils.ListSpec    (listSpec)
import           Utils.TupleSpec   (tupleSpec)


main :: IO ()
main = hspec $ do
  listSpec
  tupleSpec
  merkleSpec
