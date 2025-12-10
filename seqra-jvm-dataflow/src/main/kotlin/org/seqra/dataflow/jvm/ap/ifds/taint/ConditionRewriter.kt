package org.seqra.dataflow.jvm.ap.ifds.taint

import org.seqra.dataflow.configuration.jvm.And
import org.seqra.dataflow.configuration.jvm.Condition
import org.seqra.dataflow.configuration.jvm.ConditionVisitor
import org.seqra.dataflow.configuration.jvm.ConstantEq
import org.seqra.dataflow.configuration.jvm.ConstantGt
import org.seqra.dataflow.configuration.jvm.ConstantLt
import org.seqra.dataflow.configuration.jvm.ConstantMatches
import org.seqra.dataflow.configuration.jvm.ConstantTrue
import org.seqra.dataflow.configuration.jvm.ContainsMark
import org.seqra.dataflow.configuration.jvm.IsConstant
import org.seqra.dataflow.configuration.jvm.IsNull
import org.seqra.dataflow.configuration.jvm.Not
import org.seqra.dataflow.configuration.jvm.Or
import org.seqra.dataflow.configuration.jvm.TypeMatches
import org.seqra.dataflow.configuration.jvm.TypeMatchesPattern

interface ConditionRewriter : ConditionVisitor<Condition> {
    override fun visit(condition: Not): Condition = Not(condition.arg.accept(this))
    override fun visit(condition: And): Condition = And(condition.args.map { it.accept(this) })
    override fun visit(condition: Or): Condition = Or(condition.args.map { it.accept(this) })

    override fun visit(condition: ConstantTrue): Condition = condition
    override fun visit(condition: IsConstant): Condition = condition
    override fun visit(condition: IsNull): Condition = condition
    override fun visit(condition: ConstantEq): Condition = condition
    override fun visit(condition: ConstantLt): Condition = condition
    override fun visit(condition: ConstantGt): Condition = condition
    override fun visit(condition: ConstantMatches): Condition = condition
    override fun visit(condition: ContainsMark): Condition = condition
    override fun visit(condition: TypeMatches): Condition = condition
    override fun visit(condition: TypeMatchesPattern): Condition = condition
}
