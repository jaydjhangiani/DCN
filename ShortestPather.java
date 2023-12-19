package edu.brown.cs.sdn.apps.sps;

import java.util.*;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.routing.Link;

/**
 * Moved to ShortestPathSwitching.java
 * this class uses bellman-ford for shortest path in directed graph,
 * which is implemented under guide of
 *      - https://algs4.cs.princeton.edu/44sp/
 */
@Deprecated
public class ShortestPather {

    private static final int WEIGHT = 1;

    public Map<Long, Integer> BellmanFord(
            IOFSwitch sourceSwitch, Collection<Link> links, Map<Long, IOFSwitch> switches) {
        Map<Long, Integer> distTo = new HashMap<>();
        Map<Long, Integer> edgeTo = new HashMap<>();
        Set<Long> onQueue = new HashSet<>();
        Queue<Long> queue = new ArrayDeque<>();

        Map<Long, ArrayList<long[]>> network = new HashMap<>();

        for (Link link: links) {
            // src -> {dst, dst port}
            network.computeIfAbsent(
                    link.getSrc(), (k -> new ArrayList<>())).add(new long[] {link.getDst(), link.getDstPort()});

            // dst -> {src, src port}
            network.computeIfAbsent(
                    link.getDst(), (k -> new ArrayList<>())).add(new long[] {link.getSrc(), link.getSrcPort()});
        }

        for (long sId: switches.keySet()) {
            distTo.put(sId, Integer.MAX_VALUE - 1);
        }
        distTo.put(sourceSwitch.getId(), 0);

        queue.offer(sourceSwitch.getId());
        onQueue.add(sourceSwitch.getId());

        while (!queue.isEmpty()) {
            long src = queue.poll();
            onQueue.remove(src);

            for (long[] lk: network.get(src)) {
                long dst = lk[0];
                if (distTo.get(dst) > distTo.get(src) + WEIGHT) {
                    distTo.put(dst, distTo.get(src) + WEIGHT);
                    edgeTo.put(dst, (int) lk[1]);

                    if (!onQueue.contains(dst)) {
                        onQueue.add(dst);
                        queue.offer(dst);
                    }
                }
            }
        }

        return edgeTo;
    }
}
