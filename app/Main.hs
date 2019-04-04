{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Crypto.Hash           (SHA256 (..), hashWith)
import           Crypto.Merkle
import           Data.ByteString       (ByteString)
import qualified Data.ByteString.Char8 as ByteString


message :: ByteString
message = "hey mr how are you doing today I hope is all good because we nedd it to bee that way"


main :: IO ()
main = do
  let words = ByteString.words message
  let res = (hashWith SHA256) <$> words
  mapM_ print res
