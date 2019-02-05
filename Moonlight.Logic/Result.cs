namespace Moonlight.Xbox.Logic
{
    using System;

    public class Result
    {
        /// <summary>
        /// This class is immutable so we can have a single success result.
        /// </summary>
        private static readonly Result SuccessfulResult = new Result(true, 0, null);

        protected Result(bool isSuccess, int errorCode, string errorMessage)
        {
            this.IsSuccess = isSuccess;
            this.ErrorCode = errorCode;
            this.ErrorMessage = errorMessage;
        }

        public bool IsSuccess { get; }

        public int ErrorCode { get; }

        public string ErrorMessage { get; }

        public static Result Succeeded()
        {
            return SuccessfulResult;
        }

        public static Result Failed(int errorCode, string errorMessage)
        {
            return new Result(false, errorCode, errorMessage);
        }

        public static Result Failed(int errorCode, Exception exception)
        {
            return new Result(false, errorCode, exception.ToString());
        }
    }

    public class Result<TResult> : Result
    {
        protected Result(bool isSuccess, int errorCode, string errorMessage, TResult value)
            : base(isSuccess, errorCode, errorMessage)
        {
            this.Value = value;
        }

        public TResult Value { get; }

        public static Result<TResult> Succeeded(TResult value)
        {
            return new Result<TResult>(true, 0, null, value);
        }

        public static new Result<TResult> Failed(int errorCode, string errorMessage)
        {
            return new Result<TResult>(false, errorCode, errorMessage, default(TResult));
        }

        public static new Result<TResult> Failed(int errorCode, Exception exception)
        {
            return new Result<TResult>(false, errorCode, exception.ToString(), default(TResult));
        }
    }
}
