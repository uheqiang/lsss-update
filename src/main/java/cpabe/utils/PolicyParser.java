package cpabe.utils;


import java.util.StringTokenizer;
//#line 23 "Parser.java"

public class PolicyParser {

    boolean lsssdebug;        //do I want debug output?
    int lssserrs;            //number of errors so far
    int lssserrflag;          //was there an error?
    int lssschar;             //the current working character

    //########## MESSAGES ##########
//###############################################################
// method: debug
//###############################################################
    void debug(String msg) {
        if (lsssdebug)
            System.out.println(msg);
    }

    //########## STACK ##########
    final static int LSSSSTACKSIZE = 500;  //maximum stack size
    int statestack[] = new int[LSSSSTACKSIZE]; //state stack
    int stateptr;
    int stateptrmax;                     //highest index of stackptr
    int statemax;                        //state when highest index reached

    //###############################################################
// methods: state stack push,pop,drop,peek
//###############################################################
    final void state_push(int state) {
        try {
            stateptr++;
            statestack[stateptr] = state;
        } catch (ArrayIndexOutOfBoundsException e) {
            int oldsize = statestack.length;
            int newsize = oldsize * 2;
            int[] newstack = new int[newsize];
            System.arraycopy(statestack, 0, newstack, 0, oldsize);
            statestack = newstack;
            statestack[stateptr] = state;
        }
    }

    final int state_pop() {
        return statestack[stateptr--];
    }

    final void state_drop(int cnt) {
        stateptr -= cnt;
    }

    final int state_peek(int relative) {
        return statestack[stateptr - relative];
    }
    //###############################################################
    // method: init_stacks : allocate and prepare stacks
    //###############################################################

    final boolean init_stacks() {
        stateptr = -1;
        val_init();
        return true;
    }

    //###############################################################
// method: dump_stacks : show n levels of the stacks
//###############################################################
    void dump_stacks(int count) {
        int i;
        System.out.println("=index==state====value=     s:" + stateptr + "  v:" + valptr);
        for (i = 0; i < count; i++)
            System.out.println(" " + i + "    " + statestack[i] + "      " + valstack[i]);
        System.out.println("======================");
    }


//########## SEMANTIC VALUES ##########


    String lssstext;//user variable to return contextual strings
    ParserVal lsssval; //used to return semantic vals from action routines
    ParserVal lssslval;//the 'lval' (result) I got from lssslex()
    ParserVal valstack[];
    int valptr;

    //###############################################################
// methods: value stack push,pop,drop,peek.
//###############################################################
    void val_init() {
        valstack = new ParserVal[LSSSSTACKSIZE];
        lsssval = new ParserVal();
        lssslval = new ParserVal();
        valptr = -1;
    }

    void val_push(ParserVal val) {
        if (valptr >= LSSSSTACKSIZE)
            return;
        valstack[++valptr] = val;
    }

    ParserVal val_pop() {
        if (valptr < 0)
            return new ParserVal();
        return valstack[valptr--];
    }

    void val_drop(int cnt) {
        int ptr;
        ptr = valptr - cnt;
        if (ptr < 0)
            return;
        valptr = ptr;
    }

    ParserVal val_peek(int relative) {
        int ptr;
        ptr = valptr - relative;
        if (ptr < 0)
            return new ParserVal();
        return valstack[ptr];
    }

    final ParserVal dup_lsssval(ParserVal val) {
        ParserVal dup = new ParserVal();
        dup.ival = val.ival;
        dup.dval = val.dval;
        dup.sval = val.sval;
        dup.obj = val.obj;
        return dup;
    }

    //#### end semantic value section ####
    public final static short ATTR = 257;
    public final static short OR = 258;
    public final static short AND = 259;
    public final static short lsssERRCODE = 256;
    final static short lssslhs[] = {-1,
            0, 1, 1, 1, 1,
    };
    final static short lssslen[] = {2,
            1, 1, 3, 3, 3,
    };
    final static short lsssdefred[] = {0,
            2, 0, 0, 0, 0, 0, 0, 5, 0, 4,
    };
    final static short lsssdgoto[] = {3,
            4,
    };
    final static short lssssindex[] = {-38,
            0, -38, 0, -253, -41, -38, -38, 0, -256, 0,
    };
    final static short lsssrindex[] = {0,
            0, 0, 0, 7, 0, 0, 0, 0, 1, 0,
    };
    final static short lsssgindex[] = {0,
            2,
    };
    final static int lsssTABLESIZE = 259;
    static short lssstable[];

    static {
        lssstable();
    }

    static void lssstable() {
        lssstable = new short[]{8,
                3, 2, 7, 5, 6, 7, 1, 9, 10, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 3, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 6, 7, 1, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 3,
        };
    }

    static short lssscheck[];

    static {
        lssscheck();
    }

    static void lssscheck() {
        lssscheck = new short[]{41,
                0, 40, 259, 2, 258, 259, 0, 6, 7, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, 41, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, 258, 259, 257, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, 258,
        };
    }

    final static short lsssFINAL = 3;
    final static short lsssMAXTOKEN = 259;
    final static String lsssname[] = {
            "end-of-file", null, null, null, null, null, null, null, null, null, null, null, null, null,
            null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null,
            null, null, null, null, null, null, null, null, null, null, "'('", "')'", null, null, null,
            null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null,
            null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null,
            null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null,
            null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null,
            null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null,
            null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null,
            null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null,
            null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null,
            null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null,
            null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null,
            null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null,
            null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null,
            null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null,
            null, null, null, null, "ATTR", "OR", "AND",
    };
    final static String lsssrule[] = {
            "$accept : result",
            "result : policy",
            "policy : ATTR",
            "policy : policy OR policy",
            "policy : policy AND policy",
            "policy : '(' policy ')'",
    };

    //#line 24 "policy_lang.y"
    private BinaryTreeNode res;
    StringTokenizer st;

    public BinaryTreeNode parse(String input) {
        input = input.replaceAll("\n", "");
        this.st = new StringTokenizer(input, " \t\r\f");
        lsssparse();
        return this.res;
    }

    private int lssslex() {
        String s;
        int tok;
        if (!st.hasMoreTokens()) {
            return 0;
        }
        s = st.nextToken();
        if (s.equals("(") || s.equals(")")) {
            tok = s.charAt(0);
            lssslval = new ParserVal(s);
        } else if (s.equals("&") || s.toLowerCase().equals("and")) {
            tok = AND;
            lssslval = new ParserVal(s);
        } else if (s.equals("|") || s.toLowerCase().equals("or")) {
            tok = OR;
            lssslval = new ParserVal(s);
        } else {
            tok = ATTR;
            lssslval = new ParserVal(s);
        }

        return tok;
    }

    public void lssserror(String error) {
        System.err.println("Error:" + error);
    }


    BinaryTreeNode leaf_policy(String attr) {
        BinaryTreeNode leaf = new BinaryTreeNode();
        leaf.setType(BinaryTreeNode.NodeType.LEAF);
        leaf.setValue(attr);

        return leaf;
    }

    BinaryTreeNode kof2_policy(int k, BinaryTreeNode l, BinaryTreeNode r) {
        BinaryTreeNode node = new BinaryTreeNode();
        node.setType(k == 1 ? BinaryTreeNode.NodeType.OR : BinaryTreeNode.NodeType.AND);
        node.setLeft(l);
        node.setRight(r);

        return node;
    }

    //#line 271 "Parser.java"
//###############################################################
// method: lssslexdebug : check lexer state
//###############################################################
    void lssslexdebug(int state, int ch) {
        String s = null;
        if (ch < 0) ch = 0;
        if (ch <= lsssMAXTOKEN) //check index bounds
            s = lsssname[ch];    //now get it
        if (s == null)
            s = "illegal-symbol";
        debug("state " + state + ", reading " + ch + " (" + s + ")");
    }


    //The following are now global, to aid in error reporting
    int lsssn;       //next next thing to do
    int lsssm;       //
    int lsssstate;   //current parsing state from state table
    String lssss;    //current token string


    //###############################################################
// method: lsssparse : parse input and execute indicated items解析输入并执行指定的项
//###############################################################
    int lsssparse() {
        boolean doaction;
        init_stacks();
        lssserrs = 0;
        lssserrflag = 0;
        lssschar = -1;          //impossible char forces a read
        lsssstate = 0;            //initial state
        state_push(lsssstate);  //save it
        val_push(lssslval);     //save empty value
        while (true) //until parsing is done, either correctly, or w/error
        {
            doaction = true;
            if (lsssdebug) debug("loop");
            //#### NEXT ACTION (from reduction table)
            for (lsssn = lsssdefred[lsssstate]; lsssn == 0; lsssn = lsssdefred[lsssstate]) {
                if (lsssdebug) debug("lsssn:" + lsssn + "  state:" + lsssstate + "  lssschar:" + lssschar);
                if (lssschar < 0)      //we want a char?
                {
                    lssschar = lssslex();  //get next token
                    if (lsssdebug) debug(" next lssschar:" + lssschar);
                    //#### ERROR CHECK ####
                    if (lssschar < 0)    //it it didn't work/error
                    {
                        lssschar = 0;      //change it to default string (no -1!)
                        if (lsssdebug)
                            lssslexdebug(lsssstate, lssschar);
                    }
                }//lssschar<0
                lsssn = lssssindex[lsssstate];  //get amount to shift by (shift index)
                if ((lsssn != 0) && (lsssn += lssschar) >= 0 &&
                        lsssn <= lsssTABLESIZE && lssscheck[lsssn] == lssschar) {
                    if (lsssdebug)
                        debug("state " + lsssstate + ", shifting to state " + lssstable[lsssn]);
                    //#### NEXT STATE ####
                    lsssstate = lssstable[lsssn];//we are in a new state
                    state_push(lsssstate);   //save it
                    val_push(lssslval);      //push our lval as the input for next rule
                    lssschar = -1;           //since we have 'eaten' a token, say we need another
                    if (lssserrflag > 0)     //have we recovered an error?
                        --lssserrflag;        //give ourselves credit
                    doaction = false;        //but don't process yet
                    break;   //quit the lsssn=0 loop
                }

                lsssn = lsssrindex[lsssstate];  //reduce
                if ((lsssn != 0) && (lsssn += lssschar) >= 0 &&
                        lsssn <= lsssTABLESIZE && lssscheck[lsssn] == lssschar) {   //we reduced!
                    if (lsssdebug) debug("reduce");
                    lsssn = lssstable[lsssn];
                    doaction = true; //get ready to execute
                    break;         //drop down to actions
                } else //ERROR RECOVERY
                {
                    if (lssserrflag == 0) {
                        lssserror("syntax error");
                        lssserrs++;
                    }
                    if (lssserrflag < 3) //low error count?
                    {
                        lssserrflag = 3;
                        while (true)   //do until break
                        {
                            if (stateptr < 0)   //check for under & overflow here
                            {
                                lssserror("stack underflow. aborting...");  //note lower case 's'
                                return 1;
                            }
                            lsssn = lssssindex[state_peek(0)];
                            if ((lsssn != 0) && (lsssn += lsssERRCODE) >= 0 &&
                                    lsssn <= lsssTABLESIZE && lssscheck[lsssn] == lsssERRCODE) {
                                if (lsssdebug)
                                    debug("state " + state_peek(0) + ", error recovery shifting to state " + lssstable[lsssn] + " ");
                                lsssstate = lssstable[lsssn];
                                state_push(lsssstate);
                                val_push(lssslval);
                                doaction = false;
                                break;
                            } else {
                                if (lsssdebug)
                                    debug("error recovery discarding state " + state_peek(0) + " ");
                                if (stateptr < 0)   //check for under & overflow here
                                {
                                    lssserror("Stack underflow. aborting...");  //capital 'S'
                                    return 1;
                                }
                                state_pop();
                                val_pop();
                            }
                        }
                    } else            //discard this token
                    {
                        if (lssschar == 0)
                            return 1; //lsssabort
                        if (lsssdebug) {
                            lssss = null;
                            if (lssschar <= lsssMAXTOKEN) lssss = lsssname[lssschar];
                            if (lssss == null) lssss = "illegal-symbol";
                            debug("state " + lsssstate + ", error recovery discards token " + lssschar + " (" + lssss + ")");
                        }
                        lssschar = -1;  //read another
                    }
                }//end error recovery
            }//lsssn=0 loop
            if (!doaction)   //any reason not to proceed?
                continue;      //skip action
            lsssm = lssslen[lsssn];          //get count of terminals on rhs
            if (lsssdebug)
                debug("state " + lsssstate + ", reducing " + lsssm + " by rule " + lsssn + " (" + lsssrule[lsssn] + ")");
            if (lsssm > 0)                 //if count of rhs not 'nil'
                lsssval = val_peek(lsssm - 1); //get current semantic value
            lsssval = dup_lsssval(lsssval); //duplicate lsssval if ParserVal is used as semantic value
            switch (lsssn) {
//########## USER-SUPPLIED ACTIONS ##########
                case 1:
//#line 15 "policy_lang.y"
                {
                    res = (BinaryTreeNode) val_peek(0).obj;
                }
                break;
                case 2:
//#line 17 "policy_lang.y"
                {
                    lsssval.obj = leaf_policy(val_peek(0).sval);
                }
                break;
                case 3:
//#line 18 "policy_lang.y"
                {
                    lsssval.obj = kof2_policy(1, (BinaryTreeNode) val_peek(2).obj, (BinaryTreeNode) val_peek(0).obj);
                }
                break;
                case 4:
//#line 19 "policy_lang.y"
                {
                    lsssval.obj = kof2_policy(2, (BinaryTreeNode) val_peek(2).obj, (BinaryTreeNode) val_peek(0).obj);
                }
                break;
                case 5:
//#line 20 "policy_lang.y"
                {
                    lsssval = val_peek(1);
                }
                break;
//#line 440 "Parser.java"
//########## END OF USER-SUPPLIED ACTIONS ##########
            }//switch
            //#### Now let's reduce... ####
            if (lsssdebug) debug("reduce");
            state_drop(lsssm);             //we just reduced lssslen states
            lsssstate = state_peek(0);     //get new state
            val_drop(lsssm);               //corresponding value drop
            lsssm = lssslhs[lsssn];            //select next TERMINAL(on lhs)
            if (lsssstate == 0 && lsssm == 0)//done? 'rest' state and at first TERMINAL
            {
                if (lsssdebug) debug("After reduction, shifting from state 0 to state " + lsssFINAL + "");
                lsssstate = lsssFINAL;         //explicitly say we're done
                state_push(lsssFINAL);       //and save it
                val_push(lsssval);           //also save the semantic value of parsing
                if (lssschar < 0)            //we want another character?
                {
                    lssschar = lssslex();        //get next character
                    if (lssschar < 0) lssschar = 0;  //clean, if necessary
                    if (lsssdebug)
                        lssslexdebug(lsssstate, lssschar);
                }
                if (lssschar == 0)          //Good exit (if lex returns 0 ;-)
                    break;                 //quit the loop--all DONE
            }//if lsssstate
            else                        //else not done yet
            {                         //get next state and push, for next lsssdefred[]
                lsssn = lsssgindex[lsssm];      //find out where to go
                if ((lsssn != 0) && (lsssn += lsssstate) >= 0 &&
                        lsssn <= lsssTABLESIZE && lssscheck[lsssn] == lsssstate)
                    lsssstate = lssstable[lsssn]; //get new state
                else
                    lsssstate = lsssdgoto[lsssm]; //else go to new defred
                if (lsssdebug)
                    debug("after reduction, shifting from state " + state_peek(0) + " to state " + lsssstate + "");
                state_push(lsssstate);     //going again, so push state & val...
                val_push(lsssval);         //for next action
            }
        }//main loop
        return 0;//lsssaccept!!
    }
//## end of method parse() ######################################


//## run() --- for Thread #######################################

    /**
     * A default run method, used for operating this parser
     * object in the background.  It is intended for extending Thread
     * or implementing Runnable.  Turn off with -Jnorun .
     */
    public void run() {
        lsssparse();
    }
//## end of method run() ########################################


//## Constructors ###############################################

    /**
     * Default constructor.  Turn off with -Jnoconstruct .
     */
    public PolicyParser() {
        //nothing to do
    }


    /**
     * Create a parser, setting the debug to true or false.
     *
     * @param debugMe true for debugging, false for no debug.
     */
    public PolicyParser(boolean debugMe) {
        lsssdebug = debugMe;
    }
//###############################################################


}
//################### END OF CLASS ##############################

