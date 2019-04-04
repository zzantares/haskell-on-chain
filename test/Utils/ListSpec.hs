module Utils.ListSpec where

import           Test.Hspec
import           Utils.List (byTwo)


listSpec :: Spec
listSpec = do
  describe "### Utils.List.byTwo" $ do
    it "organizes by two on an even length list" $ do
      let sample   = [1, 2, 3, 4, 5, 6] :: [Integer]
          expected = [(1, 2), (3, 4), (5, 6)] :: [(Integer, Integer)]
      byTwo sample `shouldBe` expected

    it "organizes by two on an odd length list" $ do
      let sample   = [1, 2, 3, 4, 5] :: [Integer]
          expected = [(1, 2), (3, 4), (5, 5)] :: [(Integer, Integer)]
      byTwo sample `shouldBe` expected
