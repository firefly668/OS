#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

/* 定义 fixed_t */
typedef int fixed_t;
/*用于移位*/
#define SHIFT_NUMBER (1<<14)

#define CONVERT_TO_FIXED(A) (A * SHIFT_NUMBER)

#define CONVERT_TO_INT_ROUND_ZERO(A) (A / SHIFT_NUMBER)

#define CONVERT_TO_INT_ROUND_NEAR(A) ((A >= 0)?((A+SHIFT_NUMBER/2)/SHIFT_NUMBER):((A-SHIFT_NUMBER/2)/SHIFT_NUMBER))

#define ADD_TWO_FIXED(A,B) (A+B)

#define SUB_TWO_FIXED(A,B) (A-B)

#define ADD_FIXED_INT(A,B) (A+B*SHIFT_NUMBER)

#define SUB_FIXED_INT(A,B) (A-B*SHIFT_NUMBER)

#define MUL_TWO_FIXED(A,B) (((int64_t)A)*B/SHIFT_NUMBER)

#define MUL_FIXED_INT(A,B) (A*B)

#define DIV_TWO_FIXED(A,B) (((int64_t)A)*SHIFT_NUMBER/B)

#define DIV_FIXED_INT(A,B) (A/B)

#endif /* thread/fixed_point.h */