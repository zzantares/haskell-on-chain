module Utils.TupleSpec where

import           Prelude     hiding (elem)
import           Test.Hspec
import           Utils.Tuple (elem)


tupleSpec :: Spec
tupleSpec =
  describe "### Utils.Tuple.elem" $
    it "finds out if given element is in the tuple" $ do
      let pair = (1, 2) :: (Int, Int)

      elem 1 pair `shouldBe` True
      elem 2 pair `shouldBe` True
      elem 3 pair `shouldBe` False
