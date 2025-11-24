package org.seqra.dataflow.jvm.ap.ifds.taint

import org.seqra.dataflow.configuration.jvm.Condition
import org.seqra.dataflow.configuration.jvm.ConditionVisitor
import org.seqra.dataflow.configuration.jvm.Position
import org.seqra.dataflow.configuration.jvm.TaintMark
import java.util.Objects

@Suppress("EqualsOrHashCode")
data class ContainsMarkOnAnyField(
    val position: Position,
    val mark: TaintMark,
) : Condition {
    override fun <R> accept(conditionVisitor: ConditionVisitor<R>): R {
        error("Condition visitor is not supported")
    }

    private val hash = Objects.hash(position, mark)
    override fun hashCode(): Int = hash
}
