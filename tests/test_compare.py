from apkdiff.compare import compare_methods, parse_method_descriptor


def test_parse_method_descriptor_with_object_and_primitive() -> None:
    params, ret = parse_method_descriptor("(Ljava/lang/String;I)Z")
    assert params == ["java.lang.String", "int"]
    assert ret == "boolean"


def test_parse_method_descriptor_with_arrays() -> None:
    params, ret = parse_method_descriptor("([[I[Ljava/lang/String;)V")
    assert params == ["int[][]", "java.lang.String[]"]
    assert ret == "void"


def test_compare_methods_detects_return_change() -> None:
    before = {"A->m(int)": "java.lang.String", "A->x()": "void"}
    after = {"A->m(int)": "retrofit2.Response", "A->y()": "void"}

    result = compare_methods(before, after)
    assert result["before_only_methods"] == ["A->x()"]
    assert result["after_only_methods"] == ["A->y()"]
    assert result["return_type_changed"] == [
        {
            "method": "A->m(int)",
            "before_return": "java.lang.String",
            "after_return": "retrofit2.Response",
        }
    ]
