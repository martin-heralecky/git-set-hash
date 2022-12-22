# git-set-hash

Because every important commit deserves a cool hash.

## Installation

```
make clean install
```

## Example

<pre>
$ git commit -m "my message"

$ <b>git set-hash cafe0000</b>
computing hashes on 16 threads...
found magic: 81rv1U
[<b>cafe0000</b>2a5d3386f5fd09bf605d776579384990] my message

$ git show
commit <b>cafe0000</b>2a5d3386f5fd09bf605d776579384990 (HEAD -> master)
Author: Martin Heralecký <heralecky.martin@gmail.com>
Date:   Thu Dec 22 19:56:48 2022 +0100

    my message

    magic: 81rv1U
</pre>

## Use Cases

"Linear" history.

<pre>
* <b>00000003</b> delete file
* <b>00000002</b> change file
* <b>00000001</b> add file
* <b>00000000</b> initial commit
</pre>

Versioning. No need for tags.

<pre>
* <b>02005014</b> release version 2.5.14
* ...
* <b>02005013</b> release version 2.5.13
</pre>

Indicating breaking changes (BC).

<pre>
* <b>bc000043</b> remove deprecated features
</pre>

You can also use hashes to log time spent on each commit, reference an issue number from your issue tracker, keep track of when (date/time) the commit was made, or even play tic-tac-toe with your co-workers.
