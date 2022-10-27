
def explode(by, s):
    return s.split(by)
def implode(by, a):
    if isinstance(a, list):
        return by.join(a)
    raise TypeError('Not a list')
def count(a):
    return len(a)
def strlen(a):
    return len(a)
def array_reverse(array):
    copy = array[:]
    copy.reverse()
    return copy
def ucfirst(s):
    if len(s) > 1:
        return s[0].upper() + s[1:]
    if len(s):
        return s[0].upper()
    return s

STDOUT = STDERR = 0
def fprintf(dst, fmt, *args):
    print(fmt, *args)

false = False
true = True

_possible_lame = ["notte", "noted", "ally", "waist"] # not nor fees hans use used uses seas sieze bath bathe
_possible_replacements = ["titan", "bull", "tub", "io", "on", "to", "at", "in", "penis", "fuji", "xerox", "dwarf", "pluto", "venus", "xena", "eros", "ida", ]
_changes = {
        'ally': 'alley',
        'acres': 'acre',
        'allen': 'alan',
        'lense': 'lens', # common mispelling
        'luis' : 'louis', # alternative spelling
        'goes' : 'go',
        'pee'  : 'pea', # alternative spelling
        'hi'   : 'high', # alternative spelling
        'waist': 'venus', # changed (but existing 'waste' conflicted)
        'witch': 'which', # alternative spelling
        'their': 'there', # alternative
        'herd':  'heard', # alternative
        'maid':  'no', # alternative (but existing 'made' conflicted)
        'mail':  'trump', # alternative (but existing 'mail' conflicted)
        'boar':  'bore', # alternative
}
_dictWords = [
    "able", "about", "above", "ache", "acid", "acre", "act", "actor", "adapt", "add", "admit", "adopt", "after", "again", "age", "agent", "ago", "agree", "ahead", "aids", "aim", "air", "orgy", "alert", "alfa", "alike", "alive", "alan", "allow", "alley",
    "alone", "along", "aloud", "alpha", "also", "alter", "among", "amuse", "and", "anger", "angle", "anglo", "angry", "annoy", "anode", "apart", "apple", "apply", "april", "arc", "arch", "are", "area", "argue", "arise", "arm", "armed", "army", "arrow",
    "art", "ash", "aside", "asked", "asset", "atom", "negro", "fag", "auto", "avoid", "awake", "award", "aware", "away", "axis", "baby", "back", "bad", "badly", "bag", "bake", "baker", "ball", "band", "bank", "bar", "bare", "barn", "base", "based",
    "basic", "basin", "bath", "bathe", "bay", "beach", "beak", "beam", "bean", "bear", "beard", "beast", "beat", "bed", "beef", "been", "beer", "beg", "began", "begin", "begun", "being", "bell", "belly", "below", "belt", "ben", "bench", "bend", "bent",
    "berry", "best", "bet", "beta", "big", "bill", "bind", "bird", "birds", "birth", "bit", "bite", "black", "blade", "blame", "bleed", "bless", "blind", "block", "blood", "blow", "blue", "board", "boast", "boat", "bob", "bod", "body", "boil", "boise",
    "bold", "bomb", "bombs", "bond", "bonds", "bone", "bones", "book", "boot", "bore", "born", "boss", "dank", "both", "bound", "bow", "bowl", "box", "boy", "brain", "brass", "brave", "bravo", "bread", "break", "bribe", "brick", "bride", "brief",
    "bring", "broad", "broke", "brown", "brush", "buck", "build", "built", "bunch", "burn", "burst", "bury", "bus", "bush", "busy", "but", "buy", "cabin", "cafe", "cage", "cake", "cali", "call", "calm", "came", "camp", "can", "cunt", "canal", "candy",
    "cap", "cape", "car", "card", "care", "carry", "cart", "case", "cash", "cast", "cat", "catch", "cathy", "cause", "cave", "cell", "cent", "chain", "chair", "chalk", "charm", "chart", "cheap", "cheat", "check", "cheek", "cheer", "chest", "chief",
    "child", "chin", "china", "chose", "chris", "cited", "city", "civic", "civil", "claim", "clark", "class", "clay", "clean", "clear", "clerk", "cliff", "climb", "clock", "close", "cloth", "cloud", "club", "coach", "coal", "coast", "coat", "code", "coin",
    "cold", "colin", "color", "comb", "come", "cook", "cool", "cope", "copy", "core", "cork", "corn", "cost", "cough", "could", "count", "court", "cover", "cow", "crack", "craft", "crash", "crazy", "cream", "creep", "crew", "cried", "crime", "crop",
    "cross", "crowd", "crown", "cruel", "crush", "cry", "cuban", "cup", "cure", "curl", "curse", "curt", "curve", "cut", "cycle", "daily", "damp", "dance", "dare", "dark", "data", "date", "dave", "dawn", "day", "dead", "deaf", "deal", "dealt", "dean",
    "dear", "death", "debby", "debt", "decay", "deck", "deed", "deep", "deer", "delay", "delta", "whore", "deny", "depth", "desk", "devil", "did", "die", "died", "diet", "dig", "dine", "dip", "dirt", "dirty", "disco", "dish", "disk", "ditch", "dive",
    "does", "dog", "doing", "done", "door", "dot", "doubt", "doug", "dover", "down", "dozen", "draft", "drag", "drain", "drama", "drank", "draw", "drawn", "dream", "dress", "drew", "dried", "drill", "drink", "drive", "drop", "drove", "drown", "drug",
    "drum", "drunk", "dry", "duck", "due", "dull", "dust", "duty", "dying", "each", "eager", "ear", "early", "earn", "earth", "ease", "east", "easy", "eat", "echo", "edge", "edit", "egg", "elder", "elect", "else", "empty", "end", "ended", "enemy", "enjoy",
    "enter", "entry", "envy", "equal", "error", "eve", "even", "event", "ever", "every", "evil", "evoke", "exact", "exert", "exist", "expel", "extra", "eye", "face", "faced", "fact", "fade", "fail", "faint", "fair", "faith", "fall", "false", "fame", "fan",
    "fancy", "far", "fare", "farm", "fast", "fat", "fate", "fault", "favor", "fear", "feast", "fed", "feed", "feel", "fees", "feet", "fell", "felt", "fence", "fever", "few", "fewer", "fiber", "field", "fig", "fight", "file", "filed", "fill", "film",
    "final", "find", "fine", "fire", "fired", "firm", "first", "fish", "fist", "fit", "five", "fix", "fixed", "flag", "flame", "flash", "flat", "fled", "flesh", "flew", "float", "flood", "floor", "flour", "flow", "fluid", "flux", "fly", "foam", "focus",
    "fog", "foil", "fold", "folk", "fond", "food", "fool", "foot", "for", "force", "ford", "fork", "form", "fort", "forth", "found", "four", "frame", "fraud", "fred", "free", "fresh", "wank", "from", "front", "fruit", "fry", "fuel", "full", "fully",
    "fun", "fund", "funny", "fur", "fuse", "gain", "game", "gamma", "gang", "gap", "gas", "gate", "gave", "gay", "gear", "gen", "germ", "get", "giant", "gift", "gin", "girl", "give", "given", "glad", "glass", "glory", "goal", "goat", "god", "go",
    "going", "gold", "golf", "gone", "good", "bitch", "got", "gov", "grace", "grade", "grain", "grand", "grant", "graph", "grass", "grave", "gray", "great", "greed", "greek", "green", "greet", "grew", "grind", "grip", "gross", "group", "grow", "guard",
    "guess", "guest", "guide", "guilt", "gulf", "gun", "guy", "habit", "hair", "hal", "half", "hall", "ham", "hand", "hang", "hans", "happy", "hard", "hardy", "harm", "harry", "haste", "hat", "hate", "have", "hay", "head", "heal", "heap", "hear", "heard",
    "heart", "heat", "heavy", "held", "helen", "hell", "hello", "help", "hen", "herd", "here", "hero", "hide", "high", "hill", "hire", "hired", "hit", "hoag", "hold", "hole", "holy", "home", "honey", "honor", "hook", "hope", "hopes", "horn", "horse",
    "host", "hot", "hotel", "hour", "house", "how", "huge", "human", "humor", "hung", "hunt", "hurry", "hurt", "hut", "ice", "idaho", "idea", "ideal", "idle", "image", "imply", "inch", "index", "india", "infer", "ink", "inn", "inner", "input", "into",
    "iowa", "iron", "issue", "item", "jail", "james", "jaw", "jazz", "jean", "jet", "jew", "jewel", "job", "join", "joint", "joke", "judge", "juice", "dick", "july", "jump", "june", "jury", "just", "cock", "keep", "kept", "key", "kick", "kid", "kill",
    "kilo", "kind", "king", "kiss", "knee", "kneel", "knew", "knife", "knock", "knot", "know", "known", "label", "labor", "lack", "lady", "laid", "lake", "lamp", "land", "lane", "large", "last", "late", "later", "latin", "laugh", "law", "lay", "layer",
    "lazy", "lead", "leaf", "lean", "learn", "least", "leave", "led", "lee", "left", "leg", "legal", "lend", "lens", "less", "let", "level", "liar", "lid", "lie", "life", "lift", "light", "like", "liked", "lima", "limb", "limit", "line", "lip", "lisa",
    "list", "live", "lived", "load", "loaf", "loan", "lobby", "local", "lock", "lodge", "log", "logic", "long", "look", "loop", "lord", "loss", "lost", "lot", "loud", "louis", "love", "loved", "lover", "low", "lower", "loyal", "luck", "lucky", "lucy",
    "lump", "lunch", "lung", "mad", "made", "magic", "no", "trump", "main", "major", "make", "male", "mama", "man", "many", "map", "march", "marry", "mars", "mason", "mass", "mat", "match", "mate", "may", "maybe", "mayor", "meal", "mean", "meant", "meat",
    "meet", "melt", "mend", "mercy", "mere", "merry", "mesa", "mess", "metal", "miami", "might", "mike", "mild", "mile", "milk", "mill", "mind", "mine", "minor", "miss", "mix", "mixed", "mode", "model", "moist", "mold", "money", "month", "mood", "moon",
    "moore", "moral", "more", "morse", "most", "motel", "motor", "mount", "mouse", "mouth", "move", "moved", "movie", "much", "mud", "music", "must", "myth", "nail", "name", "named", "clit", "nato", "navy", "near", "neat", "neck", "need", "nelly",
    "nerve", "nest", "net", "dildo", "never", "new", "newer", "newly", "news", "next", "nice", "niche", "niece", "nigel", "night", "nine", "noble", "noise", "nolan", "none", "noon", "nor", "norm", "north", "nose", "not", "note", "noted", "notte", "noun",
    "novel", "now", "nude", "null", "nurse", "nut", "oar", "obey", "occur", "ocean", "odd", "odor", "off", "offer", "often", "ohio", "oil", "okay", "old", "older", "omit", "once", "one", "only", "onset", "onto", "open", "opera", "oral", "orbit", "order",
    "pussy", "organ", "oscar", "other", "ought", "ounce", "our", "out", "outer", "over", "owe", "owen", "own", "owned", "owner", "pace", "pack", "pad", "page", "paid", "pain", "paint", "pair", "pale", "palm", "pan", "panel", "panic", "papa", "paper",
    "park", "part", "party", "pass", "past", "paste", "path", "paul", "pause", "paw", "pay", "pea", "peace", "pearl", "pen", "penny", "pest", "pet", "pete", "phase", "phone", "piano", "pick", "piece", "pig", "pike", "pile", "pilot", "pin", "pinch", "pink",
    "pint", "pip", "pipe", "pitch", "pity", "place", "plain", "plan", "plane", "plant", "plate", "plato", "play", "plead", "plot", "plow", "pluck", "plug", "plus", "poem", "poet", "pogo", "point", "pole", "pond", "pool", "poor", "pope", "porch", "port",
    "post", "pot", "pound", "pour", "power", "pray", "press", "price", "pride", "prime", "print", "prior", "prize", "proof", "proud", "prove", "pull", "pump", "pupil", "pure", "push", "put", "quart", "dong", "queen", "quick", "quiet", "quite", "quote",
    "race", "radar", "radio", "rail", "rain", "raise", "rake", "ran", "ranch", "rang", "range", "rank", "rapid", "rare", "rate", "ratio", "raw", "ray", "razor", "reach", "react", "read", "ready", "real", "rear", "rebel", "recur", "red", "refer", "rely",
    "rent", "reply", "rest", "rev", "rice", "rich", "rid", "ride", "rifle", "rigid", "rigor", "ring", "ripe", "ripen", "rise", "risk", "rita", "rival", "river", "road", "roar", "roast", "rob", "rock", "rod", "rode", "roger", "role", "roman", "rome",
    "romeo", "roof", "room", "root", "rope", "rose", "rot", "rough", "round", "route", "row", "royal", "rub", "rude", "rug", "ruin", "rule", "ruled", "run", "rural", "rush", "rust", "ruth", "sad", "safe", "said", "sail", "saint", "sake", "sale", "salem",
    "salt", "same", "san", "sand", "sandy", "sang", "santa", "sat", "sauce", "saul", "save", "saved", "saw", "say", "says", "scale", "scene", "scent", "scold", "scope", "score", "scorn", "screw", "seat", "seed", "seek", "sees", "seize", "self", "sell",
    "send", "sense", "sent", "serve", "set", "seven", "sew", "shade", "shake", "shall", "shame", "shape", "share", "sharp", "shave", "she", "shear", "sheep", "sheet", "shelf", "shell", "shift", "shine", "ship", "shirt", "shock", "shoe", "shook", "shoot",
    "shop", "shore", "short", "shot", "shout", "show", "shown", "shut", "sick", "side", "gash", "sight", "sign", "silk", "since", "sing", "sink", "sir", "sit", "site", "six", "sixth", "size", "skill", "skin", "skirt", "sky", "slave", "sleep", "slept",
    "slid", "slide", "slim", "slip", "slope", "slow", "small", "smart", "smell", "smile", "smoke", "snake", "snow", "soap", "sock", "soft", "soil", "solar", "sold", "solid", "solve", "some", "son", "song", "soon", "sore", "sorry", "sort", "soul", "sound",
    "soup", "sour", "south", "sow", "space", "spade", "span", "spare", "speak", "speed", "spend", "spent", "spill", "spin", "spit", "spite", "split", "spoil", "spoke", "spoon", "sport", "spot", "staff", "stage", "stain", "stair", "stake", "stamp", "stand",
    "star", "start", "state", "stay", "steam", "steel", "steep", "steer", "stem", "step", "stern", "stick", "stiff", "still", "sting", "stir", "stock", "stone", "stood", "stop", "store", "storm", "story", "stove", "strap", "straw", "strip", "stuck",
    "study", "stuff", "style", "such", "sugar", "suit", "suite", "sum", "sun", "sure", "swear", "sweat", "sweep", "sweet", "swell", "swept", "swift", "swim", "swing", "sword", "swung", "table", "tail", "take", "taken", "tale", "talk", "tall", "tame",
    "tampa", "tango", "tap", "tape", "task", "taste", "tax", "taxi", "tea", "teach", "team", "tear", "teeth", "tell", "tempt", "ten", "tend", "tense", "tent", "term", "test", "texas", "text", "than", "thank", "that", "the", "theft", "theme", "there",
    "these", "they", "thick", "thief", "thin", "thing", "think", "third", "this", "thorn", "those", "three", "threw", "throw", "thumb", "tide", "tidy", "tie", "tied", "tight", "till", "tim", "time", "tin", "tiny", "tip", "tire", "tired", "title", "toast",
    "today", "toe", "told", "tom", "tone", "took", "tool", "tooth", "top", "gook", "topic", "torn", "total", "touch", "tough", "tour", "towel", "tower", "town", "toy", "trace", "track", "trade", "trail", "train", "trait", "trap", "tray", "treat", "tree",
    "trend", "trial", "tribe", "trick", "tried", "trim", "trip", "truck", "true", "truly", "trunk", "trust", "truth", "try", "tube", "tulsa", "tune", "turn", "twice", "twist", "two", "type", "ugly", "uncle", "under", "union", "unit", "unite", "unity",
    "until", "upon", "upper", "upset", "urban", "urge", "urged", "usage", "use", "used", "uses", "using", "usual", "utah", "vain", "valid", "value", "van", "vary", "vast", "veil", "vein", "verb", "verse", "very", "via", "vice", "nazi", "view", "visit",
    "vital", "vivid", "voice", "volt", "vote", "voted", "vowel", "wage", "wagon", "venus", "wait", "wake", "walk", "wall", "wally", "want", "war", "ward", "warm", "warn", "was", "wash", "waste", "watch", "water", "wave", "wax", "way", "weak", "wear",
    "weave", "weed", "week", "weigh", "well", "went", "were", "west", "wet", "what", "wheat", "wheel", "when", "where", "which", "while", "whip", "lynch", "white", "who", "whole", "whom", "whose", "why", "wide", "widen", "widow", "width", "wife", "wild",
    "will", "win", "wind", "wine", "wing", "wipe", "wiped", "wire", "wise", "wish", "wit", "with", "woman", "wood", "wool", "word", "wore", "work", "worm", "worn", "worry", "worse", "worst", "worth", "would", "wound", "wrap", "wrist", "wrong", "muff",
    "yard", "year", "yell", "yes", "yet", "yield", "young", "your", "youth", "zen", "zero", "zulu"]

_dictionary = list()
_dictionaryIndex = dict()
_dictLength = 0

def _parseDictionary():
    global _dictionary, _dictWords, _dictLength, _dictionaryIndex
    if _dictionary:
        if (not count(_dictionary)):
            fprintf(STDERR, "Need to count empty _dictionary\n")
        else:
            fprintf(STDERR, "Dictionary is already populated\n")
            return
            
    _dictLength = 0
    for i, word in enumerate(_dictWords):
        _dictionary.append(word)
        _dictionaryIndex[word] = i
        _dictLength += 1
    del(_dictWords)

def _mapWord(word:str):
    global _dictionaryIndex
    return _dictionaryIndex[word]

def _mapIndex(index:int):
    global _dictionary
    return _dictionary[index]

def long_to_words(value:int):
    global _dictLength
    if (_dictLength == 0):
        _parseDictionary()
    # fprintf(STDERR, "_dictLength: %s\n", _dictLength)
    # fprintf(STDERR, "value: %s\n", value)
    words = list()
    if value < 1:
        words.append('minus')
        value = 0 - value
    while value > 0:
        componentValue = value % _dictLength
        words.append(_mapIndex(componentValue))
        # fprintf(STDERR, "componentValue: %s\n", componentValue)
        # fprintf(STDERR, "mapped: %s\n", mapped)
        value = value // _dictLength
        # fprintf(STDERR, "value: %s\n", value)

    return implode("_", words)

def words_to_long(s:str):
    global _dictLength
    if (_dictLength == 0):
        _parseDictionary()
    words = array_reverse(explode("_", s))
    # dprint("[debug] words")
    #  print("[debug] words:{}".format(words))
    
    result = 0
    minus_result = False
    for word in words:
        if word:
            if word == 'minus':
                minus_result = True
                continue
            newResult = result * _dictLength
            newResult += _mapWord(word)
            if newResult < result:
                return false
            result = newResult
    return 0 - result if minus_result else result

def snake_case(word):
    split = explode("_", word)
    return implode("", [ucfirst(x) for x in split])

# dprint("[long_to_words] long_to_words(0x12345)")
#  _parseDictionary()
# dprint("[dict] _dictWords")
#  print("[dict] _dictWords:{}".format(_dictWords))

def hashwords_test():
    l = [ida_ida.cvar.inf.min_ea, -1, 0, 1]
    # l.extend(list(range(-0xffffffff, 0xffffffff + 0xfffff, 0xffffffff)))
    for r in l:
        num = r
        val = long_to_words(num)
        renum = words_to_long(val)
        print("[long_to_words] long_to_words({}):'{}'".format(num, snake_case(val)))
        print("[words_to_long] words_to_long('{}'):{}".format(val, renum))

# hashwords_test()
# """
#
