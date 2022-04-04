---
layout: post
title:  "[RitSec CTF] Long Distance Trunk"
date:   "2022-04-03"
categories: Signal
author: isfet
---

This challenge from RitSec CTF worth 300pts and was solved by only 13 teams. 

Signal is a particular category that have challenges that requires a deep understanding of Analogical and Digital signal.

This challege says "You're not going to pay for that call, are you? +1 (585) 358-0101 or s@140.238.152.111, extension #3". So no file to download, interesting. Only a phone number is given.

With a bit of time spent by searching on internet we have found that this seems a VOIP challenge that require to call this number. This can be done with a lot of tool, we are going to use MicroSIP for Windows.

The title of this challenge can be also an hint, so we are going to use the ip instead of the number.
By calling the number we can only hear the ringing of the phone and nothing else. Again Google can help us. By searching we have found that old phones works with DMTF tones, this means that every comunication works under specific frequency that have to be provided to the phone in order to work. From the title of the challenge and from the fact that the phone seems to wait something, gave us the idea that we have to "confirm" in some way the call. This can be done with a signal of 2600hz, but how?
Google time, again.
We have found a site that can generate DMTF tones, so we have used it to play this sound in the mic during the call and boom, finally something answered out call! It's a phone dial sound and converting it gave us the flag
