package org.seqra.dataflow.jvm.ap.ifds.alias

interface ImmutableIntDSU {
    fun mutableCopy(): IntDisjointSets
}
