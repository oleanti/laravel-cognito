<div>
    Verification code delivered to {{ $details['Destination'] }}
</div>

<form method="POST" action="{{ route('cognito.verificationpost') }}">
    @csrf
    <label for="code">Code</label>
    <input id="code"
        type="text"
        name="code"
        required=""
        autocomplete="one-time-code"
        autofocus=""
        class="@error('title') is-invalid @enderror" />
    @error('code')
        <div class="alert alert-danger">{{ $message }}</div>
    @enderror
    <button type="submit">Submit</button>
</form>
