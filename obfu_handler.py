#  d810_logger = logging.getLogger('D810')
#  optimizer_logger = logging.getLogger('D810.optimizer')
import logging
pattern_search_logger = logging.getLogger('D810.pattern_search')

class OptimizationRule(object):
    NAME = None
    DESCRIPTION = None

    def __init__(self):
        self.maturities = []
        self.config = {}
        self.log_dir = None

    def set_log_dir(self, log_dir):
        self.log_dir = log_dir

    def configure(self, kwargs):
        self.config = kwargs if kwargs is not None else {}
        if "maturities" in self.config.keys():
            self.maturities = [string_to_maturity(x) for x in self.config["maturities"]]

    @property
    def name(self):
        if self.NAME is not None:
            return self.NAME
        return self.__class__.__name__

    @property
    def description(self):
        if self.DESCRIPTION is not None:
            return self.DESCRIPTION
        return "No description available"


class InstructionOptimizationRule(OptimizationRule):
    def __init__(self):
        super().__init__()
        self.maturities = DEFAULT_INSTRUCTION_MATURITIES

    def check_and_replace(self, blk, ins):
        return None


class GenericPatternRule(InstructionOptimizationRule):
    PATTERN = None
    PATTERNS = None
    REPLACEMENT_PATTERN = None

    def __init__(self):
        super().__init__()
        self.pattern_candidates = [self.PATTERN]
        if self.PATTERNS is not None:
            self.pattern_candidates += self.PATTERNS

    def check_candidate(self, candidate):
        # Perform rule specific checks
        return False

    def get_valid_candidates(self, instruction, stop_early=True):
        valid_candidates = []
        #  tmp = minsn_to_ast(instruction)
        #  if tmp is None:
            #  return []
        for candidate_pattern in self.pattern_candidates:
            if not candidate_pattern.check_pattern_and_copy_mops(tmp):
                continue
            if not self.check_candidate(candidate_pattern):
                continue
            valid_candidates.append(candidate_pattern)
            if stop_early:
                return valid_candidates
        return []

    def get_replacement(self, candidate):
        is_ok = self.REPLACEMENT_PATTERN.update_leafs_mop(candidate)
        if not is_ok:
            return None
        new_ins = self.REPLACEMENT_PATTERN.create_minsn(candidate.ea, candidate.dst_mop)
        return new_ins

    def check_and_replace(self, blk, instruction):
        valid_candidates = self.get_valid_candidates(instruction, stop_early=True)
        if len(valid_candidates) == 0:
            return None
        new_instruction = self.get_replacement(valid_candidates[0])
        return new_instruction

    @property
    def description(self):
        if self.DESCRIPTION is not None:
            return self.DESCRIPTION
        if (self.PATTERN is None) or (self.REPLACEMENT_PATTERN is None):
            return ""
        self.PATTERN.reset_mops()
        self.REPLACEMENT_PATTERN.reset_mops()
        return "{0} => {1}".format(self.PATTERN, self.REPLACEMENT_PATTERN)


class PatternMatchingRule(GenericPatternRule):
    PATTERN = None
    PATTERNS = None
    FUZZ_PATTERN = True
    REPLACEMENT_PATTERN = None

    def __init__(self):
        super().__init__()
        self.fuzz_pattern = self.FUZZ_PATTERN

    def configure(self, fuzz_pattern=None, **kwargs):
        super().configure(kwargs)
        if fuzz_pattern is not None:
            self.fuzz_pattern = fuzz_pattern
        self._generate_pattern_candidates()
        pattern_search_logger.debug("Rule {0} configured with {1} patterns"
                                    .format(self.__class__.__name__, len(self.pattern_candidates)))

    def _generate_pattern_candidates(self):
        self.fuzz_pattern = self.FUZZ_PATTERN
        if self.PATTERN is not None:
            self.PATTERN.reset_mops()
        if not self.fuzz_pattern:
            if self.PATTERN is not None:
                self.pattern_candidates = [self.PATTERN]
                if self.PATTERNS is not None:
                    self.pattern_candidates += [x for x in self.PATTERNS]
            else:
                self.pattern_candidates = [x for x in self.PATTERNS]
        else:
            self.pattern_candidates = ast_generator(self.PATTERN)

    def check_candidate(self, candidate):
        return True

    def check_pattern_and_replace(self, candidate_pattern, test_ast):
        if hasattr(test_ast, 'blk'):
            self.blk = test_ast.blk
        if hasattr(test_ast, 'ins'):
            candidate_pattern.ins = test_ast.ins
        if not candidate_pattern.check_pattern_and_copy_mops(test_ast):
            return None
        if not self.check_candidate(candidate_pattern):
            return None
        new_instruction = self.get_replacement(candidate_pattern)
        return new_instruction

class ReplaceMovHigh(PatternMatchingRule):
    # PATTERN = AstNode(m_mov, AstConstant('c_0'))
    # REPLACEMENT_PATTERN = AstNode(m_or, AstConstant("new_c_0"), AstNode(m_and, AstLeaf("new_reg"), AstConstant("mask")))

    def check_candidate(self, candidate):
        # IDA does not do constant propagation for pattern such as:
        # mov     #0x65A4.2, r6.2
        # mov     #0x210F.2, r6^2.2
        # jz      r0.4, r6.4
        # Thus, we try to detect mov to r6^2 and replace by (or #0x210F0000.4, r6.4 & 0x0000ffff.4, r6.4
        # By doing that, IDA constant propagation will work again.

        if candidate.dst_mop.t != mop_r:
            return False
        dst_reg_name = format_mop_t(candidate.dst_mop)
        if dst_reg_name is None:
            return False
        if "^2" in dst_reg_name:
            if candidate["c_0"].mop.size != 2:
                return False
            candidate.add_constant_leaf("new_c_0", candidate["c_0"].value << 16, 4)
            candidate.add_constant_leaf("mask", 0xffff, 4)
            new_dst_reg = mop_t()
            new_dst_reg.make_reg(candidate.dst_mop.r - 2, 4)
            candidate.add_leaf("new_reg", new_dst_reg)
            candidate.dst_mop = new_dst_reg
            return True
        else:
            return False
