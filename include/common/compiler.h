#ifndef __COMPILER_H__
#define __COMPILER_H__

#if defined(__clang__)

# define FALL_THROUGH [[clang::fallthrough]]

#elif defined(__GNUC__)

# if __GNUC__  > 6
#  define FALL_THROUGH __attribute__ ((fallthrough))
# else
#  define FALL_THROUGH
# endif

#else

# define FALL_THROUGH

#endif

#endif // __COMPILER_H__
