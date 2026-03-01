package org.seqra.dataflow.jvm.util

import org.objectweb.asm.Opcodes
import org.seqra.ir.api.jvm.JIRMethod
import org.seqra.ir.api.jvm.cfg.JIRCallExpr

fun JIRMethod.isVararg(): Boolean =
    access and Opcodes.ACC_VARARGS != 0

fun JIRCallExpr.isVararg(): Boolean =
    method.method.isVararg()

fun JIRMethod.varargParamIdx(): Int =
    parameters.lastIndex
