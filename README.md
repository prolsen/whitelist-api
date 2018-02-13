Whitelist-API
=============

This is a simple API for creating a True/False md5hash lookup in an effort to filter out any whitelisted md5 hashes from NSRL, etc. whitelist sources.

True = Hash is in the whitelist.

False = Hash is not in the whitelist.

Response
=========

hxxp://192[.]168[.]1[.]3:1234/sysforensics/api/v0.1/hash/392126e756571ebf112cb1c1cdedf926

        {
          "in_set": true, 
          "md5_hash": "392126e756571ebf112cb1c1cdedf926"
        }
        
hxxp://192[.]168[.]1[.]3:1234/sysforensics/api/v0.1/hash/392126e756571ebf112cb1c1cde00000

        {
          "in_set": false, 
          "md5_hash": "392126e756571ebf112cb1c1cde00000"
        }
