# rfinger

Rust app for manageing profile pictures on s3. It allows setting either interactively or through api.

## Documentation

Ducumentation can be found under https://rfinger.datasektionen.se/docs/api

`GET /api/:kthid>`, returns a presigned url that can be put in an img tag

## Development

There is a compose file that mostly works, it is still dependent on production Hive. Might have to change the region and path style in the s3 client config.
