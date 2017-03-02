#include "module.h"

namespace module {

// unknown arguments are ignored
bool Module::parse(int argc, char * argv[], std::map <std::string, std::string> & args) const{
    std::vector <std::string>::size_type pos = 0;
    for(int i = 0; i < argc; i++){
        if (argv[i][0] == '-'){
            if (optional.find(argv[i] + 1) != optional.end()){
                args[argv[i] + 1] = argv[i + 1];
                i++;// skip value
            }
            else{
                std::cerr << "Warning: Unknown optional argument: " << argv[i] << std::endl;
            }
        }
        else{
            // set positional argument
            if (pos < positional.size()){
                // if positional argument isn't already in the arguments list
                if (args.find(positional[pos]) == args.end()){
                    args[positional[pos]] = argv[i];
                    pos++;
                }
            }
        }
    }

    return (pos >= positional.size());
}

Module::Module(const Module & cmd)
    : name(cmd.name),
      positional(cmd.positional),
      optional(cmd.optional),
      run(cmd.run)
{}

Module::Module(Module && cmd)
    : name(std::move(cmd.name)),
      positional(std::move(cmd.positional)),
      optional(std::move(cmd.optional)),
      run(std::move(cmd.run))
{}

Module::Module(const std::string & n,
               const std::vector <std::string> & pos,
               const std::map <std::string, std::pair <std::string, std::string> >  & opt,
               std::function <int(std::map <std::string, std::string> &)> & func)
    : name(),
      positional(),
      optional(),
      run()
{
    // check for whitespace in name
    for(char const & c : n){
        if (std::isspace(c)){
            throw std::runtime_error("Error: Whitespace found in name: " + n);
        }
    }

    // make sure there aren't duplicate positional arguements
    std::vector <std::string> pos_cp = positional;
    std::sort(pos_cp.begin(), pos_cp.end());
    for(std::size_t i = 1; i < pos_cp.size(); i++){
        if (pos_cp[i - 1] == pos_cp[i]){
            throw std::runtime_error("Error: Duplicate postional arguments found: " + pos_cp[i]);
        }
    }


    // check for whitespace in option flags
    for(std::pair <const std::string, std::pair <std::string, std::string> > const & option : optional){
        for(char const & c : option.first){
            if (std::isspace(c)){
                throw std::runtime_error("Error: Whitespace found in option flag: " + option.first);
            }
        }
    }

    // only set values after input passes
    name = n;
    positional = pos;
    optional = opt;
    run = func;
}

Module & Module::operator=(const Module & cmd){
    name        = cmd.name;
    positional  = cmd.positional;
    optional    = cmd.optional;
    run         = cmd.run;
    return *this;
}

Module & Module::operator=(Module && cmd){
    name        = std::move(cmd.name);
    positional  = std::move(cmd.positional);
    optional    = std::move(cmd.optional);
    run         = std::move(cmd.run);
    return *this;
}

const std::string & Module::get_name() const{
    return name;
}

std::string Module::help(const std::string & indent) const{
    std::string help_str = indent + name;

    // append positional arugments
    for(std::string const & p : positional){
        help_str += " " + p;
    }

    // add "[options]" marker
    if (optional.size()){
        help_str += " [options]\n" + indent + "    options:\n";
    }

    // process optional arguments
    for(std::pair <const std::string, std::pair <std::string, std::string> > const & kv : optional){
        // build help string
        help_str += indent + "        -" + kv.first + " " + kv.second.first + "; default value: \"" + kv.second.second + "\"\n";
    }

    return help_str;
}

int Module::operator()(int argc, char * argv[]) const{
    // fill arguments with optional arguments
    std::map <std::string, std::string> args;
    for(std::pair <const std::string, std::pair <std::string, std::string> > const & kv : optional){
        args[kv.first] = kv.second.second;
    }

    // parse input arguments
    if (!parse(argc, argv, args) || (run(args) == -1)){
        std::cout << help() << std::endl;
        return -1;
    }

    return 0;
}

// force all characters to lowercase
std::string lower(const std::string & in){
    std::string out = "";
    for(char const & c : in){
        out += std::string(1, tolower(c));
    }
    return out;
}

// force all characters to uppercase
std::string upper(const std::string & in){
    std::string out = "";
    for(char const & c : in){
        out += std::string(1, toupper(c));
    }
    return out;
}

// Output data into a file, or if not possible, to stdout
void output(const std::string & data, const std::string & filename){
    if (filename != ""){
        try{
            std::ofstream out(filename.c_str(), std::ios::binary);
            if (!out){
                throw std::runtime_error("Error: File " + filename + " could not be opened.");
            }

            out << data;
        }
        catch (const std::exception & e){
            std::cerr << "Error: " << e.what() << "\n" << data << std::endl;
        }
    }
    else{
        std::cout << data << std::endl;
    }
}

}
