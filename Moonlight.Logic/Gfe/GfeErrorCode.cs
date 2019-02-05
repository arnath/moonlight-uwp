namespace Moonlight.Xbox.Logic.Gfe
{
    public enum GfeErrorCode
    {
        None = 0,
        UnknownError,
        HttpError,
        HttpInvalidResponse,
        PairingInvalidSignature,
        PairingIncorrectPin,
        PairingAlreadyInProgress
    }
}
