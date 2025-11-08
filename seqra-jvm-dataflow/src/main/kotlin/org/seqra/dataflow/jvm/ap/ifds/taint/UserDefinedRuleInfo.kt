package org.seqra.dataflow.jvm.ap.ifds.taint

import org.seqra.dataflow.configuration.jvm.serialized.ItemInfo

interface UserDefinedRuleInfo: ItemInfo {
    val relevantTaintMarks: Set<String>
}
