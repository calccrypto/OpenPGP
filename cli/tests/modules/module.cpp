#include <sstream>

#include <gtest/gtest.h>

#include "cli/modules/module.h"
#include "tests/read_pgp.h"

class TestModule : public module::Module {
    public:
        TestModule(const std::string                & n,
                   const std::vector <std::string>  & pos,
                   const Opts                       & opts,
                   const Flags                      & flags,
                   const Run                        & func)
            : Module(n, pos, opts, flags, func)
        {}

        const std::string get_name() const {
            return name;
        }

        const std::vector <std::string> & get_positional() const {
            return positional;
        }
};

static int do_nothing(const std::map <std::string, std::string> & /* args  */,
                      const std::map <std::string, bool>        & /* flags */,
                      std::ostream                              & /* out   */,
                      std::ostream                              & /* err   */) {
    return 0;
}

TEST(Module, Constructor) {
    // bad name
    {
        EXPECT_THROW(module::Module("bad name",
                                    {},
                                    {},
                                    {},
                                    do_nothing), std::runtime_error);
    }

    // bad optional argument name
    {
        EXPECT_THROW(module::Module("good_name",
                                    {},
                                    {std::make_pair("bad optional argument", std::make_pair("", ""))},
                                    {},
                                    do_nothing), std::runtime_error);
    }

    // bad flag name
    {
        EXPECT_THROW(module::Module("good_name",
                                    {},
                                    {},
                                    {std::make_pair("bad flag", std::make_pair("", false))},
                                    do_nothing), std::runtime_error);
    }

    // duplicate positional argument name
    {
        EXPECT_THROW(module::Module("good_name",
                                    {"positionalargument", "positionalargument"},
                                    {},
                                    {},
                                    do_nothing), std::runtime_error);
    }

    // duplicate positional/optional argument
    {
        EXPECT_THROW(module::Module("good_name",
                                    {"optional"},
                                    {std::make_pair("optional", std::make_pair("", ""))},
                                    {},
                                    do_nothing), std::runtime_error);
    }

    // duplicate positional argument/flag
    {
        EXPECT_THROW(module::Module("good_name",
                                    {"flag"},
                                    {},
                                    {std::make_pair("flag", std::make_pair("", false))},
                                    do_nothing), std::runtime_error);
    }

    // duplicate optional argument/flag
    {
        EXPECT_THROW(module::Module("good_name",
                                    {},
                                    {std::make_pair("optional", std::make_pair("",    ""))},
                                    {std::make_pair("optional", std::make_pair("", false))},
                                    do_nothing), std::runtime_error);
    }

    // duplicate optional arguments and flags are allowed; last value is kept
    {
        EXPECT_NO_THROW(module::Module("good_name",
                                       {},
                                       {std::make_pair("optional", std::make_pair("", "")), std::make_pair("optional", std::make_pair("", ""))},
                                       {std::make_pair("flag", std::make_pair("", false)),  std::make_pair("flag", std::make_pair("", false))},
                                       do_nothing)
                       );
    }

    // extra argument
    {
        int argc = 1;
        char * argv[] = {(char *) "extra arg"};
        std::stringstream out, err;
        EXPECT_NO_THROW(module::Module("good_name",
                                       {},
                                       {},
                                       {},
                                       do_nothing)(argc, argv, out, err)
                       );
    }

    // good module
    {
        EXPECT_NO_THROW(module::Module("good_name",
                                       {"arg1", "arg2"},
                                       {std::make_pair("opt1", std::make_pair("optional argument 1", "1")), std::make_pair("opt2", std::make_pair("optional argument 2", "2"))},
                                       {std::make_pair("flag1", std::make_pair("flag 1", true)), std::make_pair("flag2", std::make_pair("flag 2", false))},
                                       do_nothing)
                       );
    }
}
