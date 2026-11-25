# Availability: what happens when splintd itself fails

The honest question a reviewer asks about any inline mediator is: if the thing
you put in front of the driver crashes, what happens to the system behind it?
QSplintNX has a specific answer, and it depends on the interposition mode. All
of the runs below are on the QNX 8.0 QEMU/KVM target; `demo/run_fail.sh`
reproduces them.

## Relocated mode fails closed

In relocated mode the driver runs on a hidden backend path and `splintd` owns the
public path clients use. secpol grants `channel connect` to the driver's channel
(type `vendor_can_t`) only to `splintd`'s type. That rule lives in the kernel's
security policy, not inside `splintd`.

When `splintd` is killed (`kill -9`), the resource manager detaches, so the
public node disappears:

    kill -9 <splintd>
    ls -l /dev/vendor_can            -> No such file or directory
    can_client -p /dev/vendor_can    -> open(...): No such file or directory
    can_client -p /dev/.splint/...   -> open(...): Operation not permitted
    pidin -p vendor_can              -> vendor_can   (still alive, unreachable)

The device becomes unavailable, and the vulnerable driver is **not** exposed:
the direct-to-backend open is still denied, because the deny is enforced by the
kernel's secpol and does not depend on `splintd` being alive. A crash of the
mediator cannot re-expose the asset it was protecting. This is the property that
makes the mediation trustworthy: it is kernel-enforced, not mediator-enforced.

Restarting `splintd` restores availability, and because the driver process never
died, its state is intact:

    (restart splintd)
    ls -l /dev/vendor_can            -> present again
    can_client ... -n 10             -> connected (filters=8), sent=10 errors=0

## Shadow mode fails open

Shadow mode leaves the driver on its original public path and puts `splintd` in
front with `_RESMGR_FLAG_BEFORE`. If `splintd` dies, its "before" attach is gone
but the driver's own attach on the same path remains, so clients now reach the
driver directly, unprotected:

    (splintd shadowing, patch loaded)
    exploit -p /dev/vendor_can       -> TRIGGER: blocked
    kill -9 <splintd>
    ls -l /dev/vendor_can            -> present (the driver's own node)
    exploit -p /dev/vendor_can       -> TRIGGER: driver crashed   (re-exposed)

Shadow mode is the right tool when the device must stay reachable and losing the
patch is acceptable; relocated mode is the right tool when re-exposing the driver
is not acceptable. For a safety- or security-critical device the recommendation
is relocated mode, so a failure of the protection layer fails closed.

## Turning a crash into a short gap

Fail-closed still means an outage while `splintd` is down. Supervising `splintd`
so it respawns keeps that window short. `demo/splint-super.sh` is a minimal
respawn loop; on target, killing the supervised `splintd` brings a new one up and
the node returns within about a second, with no manual step:

    supervised splintd pid=1257495; node up
    kill -9 1257495
    (~1-2 s later) node back, new pid=1314838
    can_client ... -n 10             -> sent=10 errors=0

For production the QNX High Availability Manager (`ham`) is the right mechanism
rather than a shell loop: register `splintd` with `ham_attach()` and a death
condition that re-launches it, which gives microkernel-supervised restart with
restart limits, logging and escalation. The behaviour is the same as the demo
supervisor; `ham` was not present in this minimal image, so the demo uses the
portable loop. Either way the combination is: relocated mode so the failure is
closed, plus supervision so availability returns on its own.

## A wedged daemon, not just a dead one

Respawn-on-exit handles a `splintd` that dies, but not one that is alive and
stuck: a deadlock, a runaway handler, or a stopped process. `demo/splint-watchdog.sh`
is a liveness watchdog that pings the control channel on a timeout and, after
repeated misses, forces `splintd` down (SIGCONT in case it was stopped, then
SIGKILL) so the supervisor respawns it. `demo/run_watchdog.sh` demonstrates it by
`SIGSTOP`-ing `splintd` (a stand-in for a wedge) and watching recovery:

    splintd up, control channel answers
    kill -STOP <splintd>                 # alive but not replying
    [watchdog] missed ping 1/2
    [watchdog] missed ping 2/2
    [watchdog] splintd (<pid>) unresponsive; forcing respawn
    [splint-super] splintd exited rc=137; respawning in 1s
    [splint-super] start #2 ... signature verified (provenance OK)
    -> new splintd running, /dev/vendor_can back

So both failure shapes are covered: the supervisor for a daemon that exits, the
watchdog for one that hangs. The gap during respawn is a genuine availability
cost of inline mediation, stated here rather than hidden: during that gap the
driver is unreachable in relocated mode, never exposed.
