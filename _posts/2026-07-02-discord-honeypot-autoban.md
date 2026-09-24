---
layout: post
title: "A Honeypot Channel to Auto-Ban Discord Spam Bots"
date: 2026-07-02
tags: [discord, java, jda, bots, moderation]
---

If you run a Discord server of any size, you've probably seen it: an account
(sometimes a brand-new bot, sometimes a real user whose account got hacked)
suddenly drops the same message in every single channel. Crypto giveaways,
"free Nitro", sketchy links, a pile of images. By the time a moderator wakes
up, the damage is done and someone has to clean up dozens of messages by hand.

I wanted something fast, automatic and dumb enough that it can't really fail.
Here's the temporary fix I landed on.

## The idea: a honeypot channel

Spam bots have one very predictable behavior: they post to **every channel
they can see**. Real users don't do that. So the trick is simple:

1. Create a channel that clearly says *"Do not write here"*.
2. Anyone who writes in it gets banned instantly.
3. The ban also deletes all their messages from the last 7 days.

A human reads the channel name and moves on. A spam bot doesn't read
anything; it just blasts the message everywhere, lands in the trap, and gets
banned before it can do much more. Since Discord's ban endpoint can wipe
recent messages at the same time, the spam in all the *other* channels
disappears in the same action.

It's the fastest approach I've found: no message scanning, no heuristics, no
waiting for a moderator. One event, one API call.

## Building it on top of my tag system

My Discord bot, Asuka, already has a system I call **tags**. Tags are labels I
attach to channels to give them specific behavior or configuration. Each tag
is a small class that receives events and knows whether the current channel
has that tag or not.

So adding the honeypot was just a matter of writing a new tag, `asuka:autoban`:

```java
package me.enz0z.asuka.tags;

import java.util.concurrent.TimeUnit;

import me.enz0z.asuka.tags.base.Tag;
import net.dv8tion.jda.api.Permission;
import net.dv8tion.jda.api.entities.channel.unions.MessageChannelUnion;
import net.dv8tion.jda.api.events.message.MessageReceivedEvent;

public class AutoBan implements Tag {

    @Override
    public String[] key() {
        return new String[] {
            "asuka:autoban",
            "Bans anyone who writes in the channel, deleting their messages from the last 7 days",
            "Useful as a honeypot against spam"
        };
    }

    @Override
    public void accept(Object _event, Boolean tagged) {
        if (tagged && _event instanceof MessageReceivedEvent) {
            MessageReceivedEvent event = (MessageReceivedEvent) _event;

            if (event.getAuthor().isBot()) return;
            if (event.getMember().hasPermission(Permission.BAN_MEMBERS)) return;
            if (!event.getGuild().getSelfMember().hasPermission(Permission.BAN_MEMBERS)) return;
            MessageChannelUnion channel = event.getChannel();

            event.getGuild()
                .ban(event.getAuthor(), 7, TimeUnit.DAYS)
                .reason("AutoBan: wrote in #" + channel.getName() + " (" + channel.getId() + ")")
                .queue(null, error -> {});
        }
    }
}
```

## How it works

- **`key()`** registers the tag: its identifier, a description, and a hint
  about what it's for.
- **`accept()`** runs for every event. If the channel has the tag and the
  event is a new message, it goes through a few safety checks:
  - Ignore other bots (so it doesn't ban Asuka itself or friendly bots).
  - Ignore anyone who already has **Ban Members** permission, so moderators
    can still post in the channel, for example to explain what it is.
  - Make sure Asuka actually has permission to ban; if not, do nothing
    instead of throwing errors.
- Then it bans the author, deletes their messages from the last **7 days**
  (the maximum Discord allows), and leaves a reason in the audit log with the
  channel name and ID, so it's obvious later why the ban happened.

The error handler is intentionally empty: if the ban fails (the user already
left, role hierarchy issues, etc.) there's nothing useful to do about it.

## Things to keep in mind

This is a pragmatic, temporary solution, not a perfect one:

- **Make the warning impossible to miss.** Channel name, topic, and a pinned
  message should all say "do not write here, you will be banned". A curious
  new member *will* test it otherwise.
- **Place it where bots will hit it.** Keep it visible to regular members,
  since spam bots only post where they have access.
- **It won't catch everything.** Spammers that target a single channel or
  only DM users will slip past it.
- **Bans can be reversed.** For hacked accounts, the real owner can appeal
  once they recover their account, and you can unban them.

## Conclusion

Sometimes the best anti-spam system isn't clever detection, it's exploiting
the one thing spam bots always do. A single tagged channel and a few lines of
JDA code turned a cleanup job of dozens of messages into an instant,
automatic ban. Until Discord gives us better tools, this does the job.
