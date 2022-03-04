/**
 * @kind path-problem
 */

 import cpp
 import semmle.code.cpp.dataflow.TaintTracking
 import DataFlow::PathGraph


 class NetworkByteSwap extends Expr {
    NetworkByteSwap() {
        exists(MacroInvocation mi |
            mi.getMacroName() in ["ntohs","ntohl","ntohll"] and
            this = mi.getExpr()
        )
    }
}

class MemcpyClass extends Function {
    MemcpyClass() {
        exists(Function f |
            f.getName() = "memcpy" and
            this = f
        )
    }
}

class Config extends TaintTracking::Configuration {
    Config() { this = "NetworkToMemFunctionLenght" }

    override predicate isSource(DataFlow::Node source) {
        source.asExpr() instanceof NetworkByteSwap   
    }

    override predicate isSink(DataFlow::Node sink) {
        exists(FunctionCall fc |
            fc.getTarget().getName() = "memcpy" and
            sink.asExpr() = fc.getArgument(2)
        )
    }
}


from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network Byte Swap Flows to memcpy"
