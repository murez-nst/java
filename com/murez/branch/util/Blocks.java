package com.murez.branch.util;

public class Blocks {
    private int[][][] blocks;
    private int left;

    public Blocks(int[][][] blocks, int left) {
        this.blocks = blocks;
        this.left = left;
    }

    public int[][][] getBlocks() { return blocks; }

    public int getLeft() { return left; }
}