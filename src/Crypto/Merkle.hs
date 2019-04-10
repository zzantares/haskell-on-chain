{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.Merkle where

import           Crypto.Hash        (Digest, HashAlgorithm, SHA256 (..),
                                     digestFromByteString, hash)
import qualified Data.ByteArray     as ByteArray (concat, convert)
import           Data.ByteString    (ByteString)
import qualified Data.ByteString    as ByteString (reverse)
import qualified Data.Char          as Char (isHexDigit)
import           Data.Either        (Either (..))
import           Data.Function      ((&))
import qualified Data.HexString     as Hex (fromBytes, hexString, toBytes,
                                            toText)
import           Data.List          (find)
import           Data.Maybe         (fromJust)
import           Data.Text          (Text)
import qualified Data.Text          as Text (all, length)
import qualified Data.Text.Encoding as Text (encodeUtf8)
import           Prelude            hiding (elem)

import           Crypto.Types       (MerkleTree (..), Tx)
import           Utils.List         (byTwo)
import           Utils.Tuple        (elem)

-- TODO: Use the IsString instance to automatically treat Strings as Digest SHA256


-- | Given two digest it combines them as Bitcoin does it.
combine :: forall a. HashAlgorithm a => Digest a -> Digest a -> Digest a
combine h g = merge h g
  & ByteString.reverse
  & doubleHash
  & ByteArray.convert
  & ByteString.reverse
  & digestFromByteString
  & fromJust
  where
    merge x y = ByteArray.concat [y, x] :: ByteString
    doubleHash a = hash (hash a :: Digest a) :: Digest a


-- | Given a 'Text' of a Hex representation SHA256 digest turns it into a Tx.
parseSHA256 :: Text -> Maybe Tx
parseSHA256 t
  | isSHA256 t = parse t
  | otherwise  = Nothing
  where
    parse = digestFromByteString . Hex.toBytes . Hex.hexString . Text.encodeUtf8


-- | Given a 'Text' of a Hex representation of a SHA256 digest determines if
-- it's an actual 'Digest SHA256'.
isSHA256 :: Text -> Bool
isSHA256 t = isHex && hasLength
  where
    isHex     = Text.all Char.isHexDigit t
    hasLength = Text.length t == 64


-- | Given two Hex digests of a SHA256 it 'combine's them and returns
-- that. 'Nothing' is returned when the given 'Text' are not valid
-- representations of a SHA256 digest.
combineSHA256 :: Text -> Text -> Maybe Text
combineSHA256 h g
  | not (isSHA256 h && isSHA256 g) = Nothing
  | otherwise = toHexText <$> maybeDigest
  where
    toHexText   = Hex.toText . Hex.fromBytes . ByteArray.convert
    maybeDigest = combine <$> parseSHA256 h <*> parseSHA256 g


-- See: https://en.bitcoin.it/wiki/Protocol_documentation#Merkle_Trees
-- API: https://blockexplorer.com/api/block/0000000000000000079c58e8b5bce4217f7515a74b170049398ed9b8428beb4a
-- | Block 10tx: 0000000000000a3290f20e75860d505ce0e948a1d1d846bec7e39015d242884b
-- | Block 15tx: 000000000000019923bbe7d72bd2b15412f6140b9cc08a262861c36e12cc8c85

-- | Sample transaction hashes (SHA3_256)
-- transactions :: [ Tx ]
-- transactions = []


-- TODO: What if an empty list is given?
-- | Computes the Merkle Tree Root of the given list of 'Tx'.
merkleRoot :: [ Tx ] -> Digest SHA256
merkleRoot txs
  | length reduced == 1 = head reduced
  | otherwise           = merkleRoot reduced
  where
    reduced = map (uncurry combine) $ byTwo txs


-- | Build a 'MerkleTree' from the given list of 'Tx'.
merkleTree :: [ Tx ] -> MerkleTree (Digest SHA256)
merkleTree = buildTree . txToLeafs


txToLeafs :: [ Tx ] -> [ MerkleTree (Digest SHA256) ]
txToLeafs txs = (\x -> Node x Leaf Leaf) <$> txs


-- It seems to be a simpler way
buildTree :: [ MerkleTree (Digest SHA256) ] -> MerkleTree (Digest SHA256)
buildTree [] = Leaf
buildTree trees
  | length nodes == 1 = head nodes
  | otherwise         = buildTree nodes
  where
    nodes = map (uncurry asNode) $ byTwo trees

    asNode :: MerkleTree (Digest SHA256) -> MerkleTree (Digest SHA256) -> MerkleTree (Digest SHA256)
    asNode Leaf Leaf                     = Leaf
    asNode l@(Node x _ _) r@(Node y _ _) = Node (combine x y) l r
    asNode _ _                           = Leaf


merkleProof :: [ Tx ] -> Tx -> [ Either (Digest SHA256) (Digest SHA256) ]
merkleProof [] _   = []
merkleProof [_] _  = []
merkleProof txs tx =
  let
    siblingOf :: Digest SHA256 -> [ (Digest SHA256, Digest SHA256) ] -> Either (Digest SHA256) (Digest SHA256)
    siblingOf x = toEither . fromJust . find (elem x)
      where
        toEither (a, b)
          | a == x    = Right b
          | otherwise = Left a

    merge :: Either (Digest SHA256) (Digest SHA256) -> Digest SHA256 -> Digest SHA256
    merge (Left h) g  = combine h g
    merge (Right h) g = combine g h

    byTwoTxs = byTwo txs
    sibling = siblingOf tx byTwoTxs
  in
    sibling : merkleProof (uncurry combine <$> byTwoTxs) (merge sibling tx)


verify :: Tx -> Digest SHA256 -> [ Either (Digest SHA256) (Digest SHA256) ] -> Bool
verify tx mkr proof = (== mkr) $ foldl prover tx proof
  where
    prover :: Digest SHA256 -> Either (Digest SHA256) (Digest SHA256) -> Digest SHA256
    prover h (Left x)  = combine x h
    prover h (Right x) = combine h x
