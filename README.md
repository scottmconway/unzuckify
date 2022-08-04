# Unzuckify

This repository contains a small Python application which allows me to
receive a notification when somebody sends me a Facebook message.

This is forked from Radian Software's repo,
which can be found [here](https://github.com/radian-software/unzuckify).

## Fork Differences
* Increased flexibility in bridging options with logging handlers (not just for email!)
* Usage of a configuration file instead of command-line args for user credentials

For more information on the project, see [Radian Software's readme](https://github.com/radian-software/unzuckify).

## Requirements
* python > 3.8
* esprima
* requests

## Configuration Setup
See `config.json.example` for an example configuration file.

### `auth_info`
This section contains the email and password fields used to authenticate to messenger.

### `cookie_file_path`
If specified, store cookies in the noted path. Defaults to `./cookies.json`.

### `logging`
`log_level` - sets the log level to subscribe to
`gotify` - only required if you wish to use gotify as a logging destination - see [gotify-handler](https://github.com/scottmconway/gotify-handler)

## Arguments
|Short Name|Long Name|Type|Description|
|-|-|-|-|
||action|`str`|`inbox`, `send`, or `read` - the command to execute|
||`--config`|`str`|Path to config file - defaults to `./config.json`|
|`-ll`|`--log-level`|`int`|If specified, overrides the log\_level parameter in the config file|
|`-n`|`--no-cookies`|`bool`|If set, ignore locally cached cookies|

Following are the arguments for each action:

`inbox`:
|Short Name|Long Name|Type|Description|
|-|-|-|-|
|`-u`|`--unread-only`|`bool`|If set, only return threads with unread messages|
||`--mark-read`|`bool`|If set, mark all currently unread threads in the inbox as read|

`read`:
|Short Name|Long Name|Type|Description|
|-|-|-|-|
|`-t`|`--thread`|`int`|The ID(s) of the thread(s) in which to send a read receipt|

`send`:
|Short Name|Long Name|Type|Description|
|-|-|-|-|
|`-t`|`--thread`|`int`|The ID of the thread in which to send a message|
|`m`|`--message`|`str`|Content of the message to send|

## Setup

If you just want to use the CLI (perhaps as proof of concept for developing your own Messenger client using the reverse engineered API), setup is quite simple. Install [Poetry](https://python-poetry.org/), run poetry install and poetry shell, then you are good to go.

## Usage

The aformentioned arguments paint a pretty good picture of what you can do with this script,
but here's _exactly_ how I use it.
My goal is to log new, unread messages to gotify, and then mark them as read (so I don't get alerted about them on the next execution).
To do so, I run the following as a cronjob:

```
*/5 * * * * cd $UNZUCK_DIR; python3 unzuckify.py inbox --unread-only --mark-read
```
