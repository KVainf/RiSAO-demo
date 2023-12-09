#pragma once

#include <functional>
#include <unordered_set>

#include "hilvl-ir.hpp"
#include "hir-common-pass.hpp"

namespace HIR {
    enum class Label {
        ingress,
        CPU,
        egress,
    };

    using LabelSet = std::unordered_set<Label>;
    using LabelInitFn = std::function<void(const Module &, const Operation &, LabelSet &)>;

    bool have_dep(const Operation& o1, const Operation& o2);
    void label(Element &ele, LabelInitFn &init_fn);

    struct PartitionResult {
        std::shared_ptr<Function> ingress;
        std::shared_ptr<Function> cpu;
        std::shared_ptr<Function> egress;

        std::unordered_set<std::shared_ptr<Var>> ingress_to_cpu_vars;
        std::unordered_set<std::shared_ptr<Var>> cpu_to_egress_vars;
    };

    PartitionResult partition(const Function &func);
}
