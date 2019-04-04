{-# LANGUAGE OverloadedStrings #-}

module Crypto.MerkleSpec where

import           Crypto.Hash        (Digest, SHA256 (..), digestFromByteString,
                                     hashWith)
import           Data.ByteString    (ByteString)
import           Data.HexString     (hexString, toBytes)
import           Data.Maybe         (fromJust)
import           Data.Text          (Text)
import           Data.Text.Encoding (encodeUtf8)

import           Crypto.Merkle
import           Crypto.Types       (MerkleTree (..))
import           Test.Hspec


merkleSpec :: Spec
merkleSpec = do
  describe "### Crypto.Merkle.combine" $
    it "combines two Digest SHA256 into one using little-endian format" $ do
      let [tx1, tx2, mkr] = fromJust . parseSHA256 <$>
            [ "ee6bc0e5f95a4ccd0f00784eab850ff8593f9045de96c6656df41c8f9f9c0888"
            , "29c59ec39fc19afd84d928272b3290bbe54558f7b51f75feb858b005dea49c10"
            , "01a5f8b432e06c11a32b3f30e6cc9a12da207b9237fddf77850801275cf4fe01"
            ]
      combine tx1 tx2 `shouldBe` mkr

  describe "### Crypto.Merkle.parseSHA256" $ do
    it "turns Text of a SHA256 hex representation into an actual Digest" $ do
      let sha256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
          expected = Just $ hashWith SHA256 ("hello" :: ByteString)
      parseSHA256 sha256 `shouldBe` expected
      parseSHA256 "abcd" `shouldBe` Nothing
      parseSHA256 "nada" `shouldBe` Nothing

  describe "### Crypto.Merkle.isSHA256" $ do
    it "validates some Text to comply with a SHA256 hex representation" $ do
      let valid = "ee6bc0e5f95a4ccd0f00784eab850ff8593f9045de96c6656df41c8f9f9c0888"
          inval =
            [ "ee6bc0e5f95a4ccd0f00784eab850ff8593f9045de96c6656df41c8f9f9c088Z"
            , "ee6bc0e5f95a4ccd0f00784ea"
            , "nada"
            ]
      isSHA256 valid `shouldBe` True
      isSHA256 <$> inval `shouldBe` [False, False, False]

  describe "### Crypto.Merkle.combineSHA256" $ do
    it "combines two Text SHA256 hex into one using little-endian format" $ do
      let txa = "ee6bc0e5f95a4ccd0f00784eab850ff8593f9045de96c6656df41c8f9f9c0888"
          txb = "29c59ec39fc19afd84d928272b3290bbe54558f7b51f75feb858b005dea49c10"
          res = "01a5f8b432e06c11a32b3f30e6cc9a12da207b9237fddf77850801275cf4fe01"
      combineSHA256 txa txb `shouldBe` Just res

  describe "### Crypto.Merkle.merkleRoot" $ do
    it "computes merkle tree root from an even list of SHA256 hex text" $ do
      -- Block: 0000000000000168fe7db3e00e748a335d39c33752c5095a85ccdab7d0184845
      let mkr = "74fe176dcfe07bf6e0ef0f9ee63c81b78623ac9b03137d5f4cfd80f0e500a7c3"
          txs =
            [ "1877fc02dfb78b83b913c0eef8fa5990a55dd4a56449faf97a0dcb6f04cff32b"
            , "94d67aa1720ef6b58d130e39f3b7b4e5e7dab07698ab6baf1465e7e639115e05"
            , "80a2726fbbe93a8a74bc5a357274510e6a00dfd50489a13c396d2c288e106ec2"
            , "5a3e9111cc3a69cc26d290578d46fb40ba1d4abcf706487a1b6d03730d3bdf02"
            ]
          rtx = fromJust $ traverse parseSHA256 txs
          expected = fromJust $ parseSHA256 mkr
      merkleRoot rtx `shouldBe` expected

    it "computes merkle tree root from an odd list of SHA256 hex text" $ do
      -- Block: 000000000000019923bbe7d72bd2b15412f6140b9cc08a262861c36e12cc8c85
      let mkr = "706f5180581389aa83dc21da0dfdc9cc3c64ca1e85aced908ff686d82844658a"
          txs =
            [ "bd35bf7bd16ad7c07a49c15e2aed3bcafb0d8f217b01bf73bcc158dcf195031e"
            , "4536f466b4e15ee0a53a8ff3c0a19a2b24dbb776ea742b20662dfb8110f50c9a"
            , "e81184e14852da31675f58abbef7275eccbc10fe93e70c7a0fd52fa8280b8244"
            , "d91d4599167d1e703276f13893900d5c16c633c3179affe806042cef0493c38b"
            , "cb9bd67e6126b515c45f297fd1447d60feaa1fcb1660b1981c94726bf4b376e4"
            , "8ca211da50198a70f77e16f6dfd229a6d512793482c4dc0b2e0bb056ca8071a6"
            , "0697ba1b4d6f7ecd9f02337807ef24426b04ff96c0846ebf0e221aee23853bba"
            , "28bfafec6d42a03184f91674f37830b13d6dd166a5cd02eacc0a53fc0d12ee96"
            , "a3384e43ca9547ec4e4a602c85c4408f47cca51cd701770d4a143c269e19705c"
            , "e4bd8b4c5e2cd2cbd08c61c3cb2e182a988aaca5e52daa73bee5b8b93110f258"
            , "125958bc3f6a043b58ddb160c7905b9bb9da7e21f59fdb4bda66bf73b8cdd581"
            , "dd029073a6b2082aa59fcbedf957f3a8bf77bffa8b20c858ff6aa1b51294628d"
            , "e0aa26ed856bef585a2600b472e73058942b41a0c695b22c6ca6870b4c5bb544"
            , "3b070d7e6a1b5498ca8849ab6e77f6dd1a1a58844071d87939c23d57aba77771"
            , "e4d9b651d8f0d76f2f4b6cee6b4701105ee3f008399305dffd32bd46d9b123fc"
            ]
          rtx = fromJust $ traverse parseSHA256 txs
          expected = fromJust $ parseSHA256 mkr
      merkleRoot rtx `shouldBe` expected

  describe "### Crypto.Merkle.merkleProof" $ do
    it "computes the merkle proof for a given Tx in a list of txs" $ do
      let toHash = fromJust . parseSHA256
          tx = toHash
            "94d67aa1720ef6b58d130e39f3b7b4e5e7dab07698ab6baf1465e7e639115e05"
          txs = toHash <$>
            [ "1877fc02dfb78b83b913c0eef8fa5990a55dd4a56449faf97a0dcb6f04cff32b"
            , "94d67aa1720ef6b58d130e39f3b7b4e5e7dab07698ab6baf1465e7e639115e05"
            , "80a2726fbbe93a8a74bc5a357274510e6a00dfd50489a13c396d2c288e106ec2"
            , "5a3e9111cc3a69cc26d290578d46fb40ba1d4abcf706487a1b6d03730d3bdf02"
            ]
          expected =
            [ Left $ toHash
              "1877fc02dfb78b83b913c0eef8fa5990a55dd4a56449faf97a0dcb6f04cff32b"
            , Right $ toHash
              "913489ac6c001574f5218a4d2d0de1d59258e663d2dfc0f091b6b302ae2cb435"
            ]
      merkleProof txs tx `shouldBe` expected

  describe "### Crypto.Merkle.verify" $ do
    it "verifies validity of Tx inclusion using the provided proof" $ do
      let toHash = fromJust . parseSHA256
          tx = toHash
            "94d67aa1720ef6b58d130e39f3b7b4e5e7dab07698ab6baf1465e7e639115e05"
          mkr = toHash
            "74fe176dcfe07bf6e0ef0f9ee63c81b78623ac9b03137d5f4cfd80f0e500a7c3"
          proof =
            [ Left $ toHash
              "1877fc02dfb78b83b913c0eef8fa5990a55dd4a56449faf97a0dcb6f04cff32b"
            , Right $ toHash
              "913489ac6c001574f5218a4d2d0de1d59258e663d2dfc0f091b6b302ae2cb435"
            ]
      proof `shouldSatisfy` verify tx mkr

  describe "### Crypto.Merkle.merkleTree" $ do
    it "builds the merkle tree from a list of Tx" $ do
      let toHash = fromJust . parseSHA256
          txs = toHash <$>
            [ "1877fc02dfb78b83b913c0eef8fa5990a55dd4a56449faf97a0dcb6f04cff32b"
            , "94d67aa1720ef6b58d130e39f3b7b4e5e7dab07698ab6baf1465e7e639115e05"
            , "80a2726fbbe93a8a74bc5a357274510e6a00dfd50489a13c396d2c288e106ec2"
            , "5a3e9111cc3a69cc26d290578d46fb40ba1d4abcf706487a1b6d03730d3bdf02"
            ]
          expected = toHash <$>
            Node "74fe176dcfe07bf6e0ef0f9ee63c81b78623ac9b03137d5f4cfd80f0e500a7c3"
              (Node "0abb8731e8103dee8ab2223d37cbc9f86399d9175c1efa709fa3edb6f6e61d84"
                (Node "1877fc02dfb78b83b913c0eef8fa5990a55dd4a56449faf97a0dcb6f04cff32b" Leaf Leaf)
                (Node "94d67aa1720ef6b58d130e39f3b7b4e5e7dab07698ab6baf1465e7e639115e05" Leaf Leaf))
              (Node "913489ac6c001574f5218a4d2d0de1d59258e663d2dfc0f091b6b302ae2cb435"
                (Node "80a2726fbbe93a8a74bc5a357274510e6a00dfd50489a13c396d2c288e106ec2" Leaf Leaf)
                (Node "5a3e9111cc3a69cc26d290578d46fb40ba1d4abcf706487a1b6d03730d3bdf02" Leaf Leaf))

      merkleTree txs `shouldBe` expected
