NOTES = []


def add_note(text):
    NOTES.append(text[:280])
    return len(NOTES)


def list_notes():
    return list(NOTES)
