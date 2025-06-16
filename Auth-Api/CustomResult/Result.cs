namespace Auth_Api.CustomResult
{
    public class Result
    {

        public Result(bool IsSuccess, Error error)
        {
            // Success Result With Error 
            if (IsSuccess && error != Error.None)
            {
                throw new Exception("Cant Result Success With Error");
            }
            if (!IsSuccess && error == Error.None)
            {
                throw new Exception("Cant Result Fail With No Error");
            }

            this.IsSuccess = IsSuccess;
            this.Error = error;
        }
        public bool IsSuccess { get; }

        public Error Error { get; }

        public static Result Success()
        {
            return new Result(true, Error.None);
        }

        public static Result Failure(Error error)
        {
            return new Result(false, error);
        }

        public static Result<Type> Success<Type>(Type value)
        {
            return new Result<Type>(value, true, Error.None);
        }

        public static Result<Type> Failure<Type>(Error error)
        {
            return new Result<Type>(default!, false, error);
        }

    }

    public class Result<Type> : Result
    {
        public Result(Type? value, bool IsSuccess, Error error) : base(IsSuccess, error)
        {
            _value = value;
        }
        private readonly Type? _value;

        public Type Value => IsSuccess ? _value! : throw new Exception("Fail Result Cant Have Value");

    }

    public class Error
    {
        public  string code;
        public  string description;

        public Error(string code, string description)
        {
            this.code = code;
            this.description = description;
        }

        public static Error None = new Error(string.Empty, string.Empty);
    }
}

