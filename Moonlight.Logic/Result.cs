namespace Moonlight.Xbox.Logic
{
    public class Result
    {
        public Result()
        {
            this.Succeeded = true;
        }

        public Result(int errorCode, string errorMessage)
        {
            this.Succeeded = false;
            this.ErrorCode = errorCode;
            this.ErrorMessage = errorMessage;
        }

        public bool Succeeded { get; set; }

        public int ErrorCode { get; set; }

        public string ErrorMessage { get; set; }
    }

    public class Result<TResult> : Result
    {
        public Result(TResult value)
        {
            this.Value = value;
        }

        public Result(int errorCode, string errorMessage)
            : base(errorCode, errorMessage)
        {
        }

        private TResult Value { get; set; }
    }
}
